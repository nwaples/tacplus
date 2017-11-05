// Package tacplus is a library for creating client and/or server TACACS+ applications.
package tacplus

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	verMajor           = 0xc               // Protocol major version
	verDefault         = verMajor<<4 | 0x0 // Default protocol version
	verDefaultMinorOne = verMajor<<4 | 0x1 // Default with minor version one

	hdrLen     = 12     // Packet header length
	maxBodyLen = 196356 // Maximum possible packet body size (AuthorResponse)

	// Packet header field offsets
	hdrVer     = 0
	hdrType    = 1
	hdrSeqNo   = 2
	hdrFlags   = 3
	hdrID      = 4
	hdrBodyLen = 8

	// Packet header flags
	hdrFlagSingleConnect = 0x04 // multiplex requests over a single connection
)

var (
	errSessionClosed    = errors.New("session closed")
	errSessionIDInUse   = errors.New("session id in use")
	errConnectionClosed = errors.New("connection closed")
	errInvalidSeqNo     = errors.New("invalid sequence number")
	errSessionNotFound  = errors.New("session not found or timed out")
	errUnexpectedEOF    = errors.New("unexpected EOF")
	errPacketQueueFull  = errors.New("packet queue full")
)

// doneContext allows a done channel to be used as a context.Context
type doneContext <-chan struct{}

func (d doneContext) Deadline() (deadline time.Time, ok bool) { return }
func (d doneContext) Done() <-chan struct{}                   { return d }
func (d doneContext) Value(key interface{}) interface{}       { return nil }

func (d doneContext) Err() error {
	select {
	case <-d:
		return context.Canceled
	default:
		return nil
	}
}

// crypt encrypts or decrypts the body of a TACACS+ packet.
func crypt(p, key []byte) {
	buf := make([]byte, len(key)+6)
	copy(buf, p[4:8])      // session id
	copy(buf[4:], key)     // shared secret
	buf[len(buf)-2] = p[0] // version
	buf[len(buf)-1] = p[2] // sequence number

	var sum []byte

	h := md5.New()
	body := p[hdrLen:]
	for len(body) > 0 {
		h.Reset()
		// write will always succeed, ignore errors
		_, _ = h.Write(buf)
		_, _ = h.Write(sum)
		sum = h.Sum(nil)
		if len(body) < len(sum) {
			sum = sum[:len(body)]
		}
		for i, c := range sum {
			body[i] ^= c
		}
		body = body[len(sum):]
	}
}

// a packet can be marshalled to and from raw bytes
type packet interface {
	marshal([]byte) ([]byte, error) // appends the encoded packet to the provided slice
	unmarshal([]byte) error         // decodes the packet
}

// writeRequest is a request to write a raw TACACS+ packet
type writeRequest struct {
	p        []byte     // raw packet
	deadline time.Time  // deadline for write
	ec       chan error // write result is returned on this channel
}

// session is a TACACS+ session
type session struct {
	id   uint32        // Session ID
	seq  uint8         // sequence number of last written packet
	in   chan []byte   // Buffered channel for incoming raw packet
	c    *conn         // Connection for session
	done chan struct{} // close channel to close session

	mu  sync.Mutex // Guards the following
	err error      // last seen error
}

func (s *session) close() {
	select {
	case <-s.done:
	case s.c.sessClose <- s:
		// send request then wait for done channel to close
		<-s.done
	}
}

func (s *session) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *session) readErr() error {
	s.mu.Lock()
	err := s.err
	s.err = errSessionClosed
	s.mu.Unlock()
	if err != nil {
		return err
	}
	err = s.c.readErr()
	if err != nil {
		return err
	}
	return errSessionClosed
}

// context returns a context.Context that is canceled when the session is closed
func (s *session) context() context.Context {
	return doneContext(s.done)
}

func (s *session) readPacket(ctx context.Context) ([]byte, error) {
	var p []byte

	// get raw packet from session in channel
	select {
	case p = <-s.in:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p == nil {
		return nil, s.readErr()
	}

	// check sequence number
	seq := p[hdrSeqNo] // packet seqno
	if seq != s.seq+1 {
		// sequence number not the same as expected

		if s.seq == 0 {
			// new session, so packet is probably the result of a previous
			// session timing out
			return p, errSessionNotFound
		}
		return p, errInvalidSeqNo
	}

	// check parity of received packet
	if seq&0x1 == s.c.parity {
		return p, errInvalidSeqNo
	}

	crypt(p, s.c.Secret)
	return p, nil
}

func (s *session) writePacket(ctx context.Context, p []byte) error {
	// don't write on closed session
	select {
	case <-s.done:
		return s.readErr()
	default:
	}

	p[hdrSeqNo]++
	s.seq = p[hdrSeqNo]

	// set body size
	binary.BigEndian.PutUint32(p[hdrBodyLen:], uint32(len(p)-hdrLen))
	crypt(p, s.c.Secret)

	wr := writeRequest{p: p, ec: make(chan error, 1)}
	if deadline, ok := ctx.Deadline(); ok {
		wr.deadline = deadline
	}

	// send write request
	select {
	case <-s.done:
		return s.readErr()
	case <-ctx.Done():
		return ctx.Err()
	case s.c.wc <- wr:
	}

	// wait for reply
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-wr.ec:
		return err
	}
}

func newSession(c *conn, id uint32) *session {
	s := &session{id: id, c: c}
	s.in = make(chan []byte, 1)
	s.done = make(chan struct{})
	return s
}

// sessReply is the result of a session create request
type sessReply struct {
	s   *session // newly created session
	err error    // error if session creation fails
}

// sessRequest is a session create request
type sessRequest struct {
	id    uint32         // Session ID
	reply chan sessReply // result of request is sent to this channel
}

// ConnConfig specifies configuration parameters for a TACACS+ connection.
//
// Setting Mux or LegacyMux allows multiplexing multiple sessions over a single network connection.
//
// Mux allows mutliplexing only if the client and server set the single-connection header flag, as described
// in https://tools.ietf.org/html/draft-grant-tacacs-02.
//
// LegacyMux assumes both ends allow multiplexing and doesn't set the single-connection header flag.
// LegacyMux overrides Mux if both are set.
//
// A mismatch between the client and server on the multiplex type can cause problems. This software
// tries to deal gracefully with some of these situations.
// A server connection will accept multiplexed sessions even if multiplexing was not set or
// negotiated, but will close the connection immediately when there are no more sessions.
// A LegacyMux server connection will set the single-connection header flag if the client does,
// allowing a Mux client to multiplex to a LegacyMux server.
//
// Timeout's are ignored if zero.
type ConnConfig struct {
	Mux          bool          // Allow sessions to be multiplexed over a single connection
	LegacyMux    bool          // Allow session multiplexing without setting the single-connection header flag
	Secret       []byte        // Shared secret key
	IdleTimeout  time.Duration // Time before closing an idle multiplexed connection with no sessions
	ReadTimeout  time.Duration // Maximum time to read a packet (not including waiting for first byte)
	WriteTimeout time.Duration // Maximum time to write a packet

	// Optional function to log errors. If not defined log.Print will be used.
	Log func(v ...interface{})
}

func (c *ConnConfig) log(v ...interface{}) {
	if c == nil || c.Log == nil {
		log.Print(v...)
	} else {
		c.Log(v...)
	}
}

// conn is a TACACS+ network connection
type conn struct {
	ConnConfig

	nc     net.Conn
	handle func(*session) // function that processes incoming sessions

	sess     map[uint32]*session // session store
	parity   uint8               // parity of sequence number for incoming packets
	mux      bool                // connection multiplexing status
	checkMux bool                // connection multiplexing to be negotatied
	idleT    *time.Timer         // idle timer

	// channels used for communicating with connection serving goroutines
	sessReq   chan sessRequest  // send a request here to create a new session
	sessClose chan *session     // send a session here to have it closed
	rc        chan []byte       // channel for incoming raw byte packets
	wc        chan writeRequest // send requests to write packets on this channel

	mu   sync.Mutex    // protects the following
	done chan struct{} // close channel to close connection
	err  error         // last error seen on connection
}

func (c *conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

func (c *conn) setErr(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

func (c *conn) readErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.err
	c.err = nil
	return err
}

// newClientSession is called by a client to create a new session.
func (c *conn) newClientSession(ctx context.Context) (*session, error) {
	for {
		// obtain session id
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint32(b)

		// new session request
		req := sessRequest{id: id, reply: make(chan sessReply)}

		// send session create request to connection
		select {
		case <-c.done:
			if err := c.readErr(); err != nil {
				return nil, err
			}
			return nil, errConnectionClosed
		case c.sessReq <- req:
			reply := <-req.reply
			if reply.err != errSessionIDInUse {
				return reply.s, reply.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// readPacketHeader reads the packet header and sets the deadline for
// reading the body.
func (c *conn) readPacketHeader() ([]byte, error) {
	h := make([]byte, hdrLen, 1024)

	var n int
	var err error
	for err == nil {
		var nn int
		nn, err = c.nc.Read(h[n:])
		// set read deadline on first successful read
		if n == 0 && nn > 0 && c.ReadTimeout > 0 && (err == nil || nn == hdrLen) {
			deadline := time.Now().Add(c.ReadTimeout)
			err = c.nc.SetReadDeadline(deadline)
		}
		n += nn
		if n == hdrLen {
			return h, nil
		}
	}
	if err == io.EOF && n > 0 {
		err = errUnexpectedEOF
	}
	return nil, err
}

func (c *conn) readPacketBody(h []byte) ([]byte, error) {
	// check body size
	s := binary.BigEndian.Uint32(h[hdrBodyLen:])
	if s > maxBodyLen {
		return nil, errors.New("packet too large")
	} else if s == 0 {
		// empty packet body, so return
		return h, nil
	}
	// expand packet to include body
	p := append(h, make([]byte, s)...)

	// read packet body
	var err error
	n := len(h)
	l := len(p)
	for err == nil {
		var nn int
		nn, err = c.nc.Read(p[n:])
		n += nn
		if n == l {
			return p, nil
		}
	}
	if err == io.EOF {
		err = errUnexpectedEOF
	}
	return nil, err
}

// readPacket reads a raw TACACS+ packet or returns an error
func (c *conn) readPacket() ([]byte, error) {
	// clear read deadline
	if c.ReadTimeout > 0 {
		if err := c.nc.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}
	// read packet header
	h, err := c.readPacketHeader()
	if err != nil {
		return nil, err
	}
	// check major version
	v := h[hdrVer]
	if v>>4 != verMajor {
		return nil, fmt.Errorf("unsupported major version %d", v>>4)
	}
	// read packet body
	return c.readPacketBody(h)
}

// readLoop reads incoming packets sending them to the connection rc channel
func (c *conn) readLoop() {
	for {
		p, err := c.readPacket()
		if err != nil {
			select {
			case <-c.done:
				// connection already closed, ignore error
			default:
				if err != io.EOF {
					c.setErr(err)
				}
				c.close()
			}
			return
		}
		select {
		case c.rc <- p:
		case <-c.done:
			return
		}
	}
}

// writeLoop accepts and processes writeRequest's for the connection
func (c *conn) writeLoop() {
	for {
		select {
		case req := <-c.wc:
			deadline := req.deadline
			if c.WriteTimeout > 0 {
				d := time.Now().Add(c.WriteTimeout)
				if deadline.IsZero() || d.Before(deadline) {
					deadline = d
				}
			}

			err := c.nc.SetWriteDeadline(deadline)
			if err == nil {
				_, err = c.nc.Write(req.p)
			}
			req.ec <- err
			if err != nil {
				c.close()
				return
			}
		case <-c.done:
			return
		}
	}
}

// processPacket queues incoming packets to a session in channel.
// If there is no session for the packet one will be created if
// possible.
func (c *conn) processPacket(p []byte) {
	// on first packet read get mux status
	if c.checkMux {
		c.mux = p[hdrFlags]&hdrFlagSingleConnect > 0
		c.checkMux = false
	}

	id := binary.BigEndian.Uint32(p[hdrID:])
	s := c.sess[id]
	if s == nil {
		// stop idle timer if connection has no sessions
		if len(c.sess) == 0 && c.idleT != nil && !c.idleT.Stop() {
			// idle timer already triggered, return and let connection close
			return
		}
		// create new session
		s = newSession(c, id)
		c.sess[id] = s
		// start session handler goroutine
		go c.handle(s)
	}
	// queue packet
	select {
	case s.in <- p:
	default:
		// Full packet queue should not happen. Close session if it does.
		c.closeSession(s)
		s.setErr(errPacketQueueFull)
	}
}

// newSession processes a client session create request and sends
// the result back on the clients reply channel.
func (c *conn) newSession(sr sessRequest) {
	var r sessReply
	if !c.mux && len(c.sess) > 0 {
		r.err = errors.New("session multiplexing not supported")
	} else if _, ok := c.sess[sr.id]; ok {
		r.err = errSessionIDInUse
	} else if len(c.sess) == 0 && c.idleT != nil && !c.idleT.Stop() {
		// Stopped running idle timer but it had already triggered.
		// Return error and allow connection to close.
		r.err = errConnectionClosed
	} else {
		r.s = newSession(c, sr.id)
		c.sess[sr.id] = r.s
	}
	sr.reply <- r
}

func (c *conn) closeSession(s *session) {
	if s != c.sess[s.id] {
		// session already closed
		return
	}
	delete(c.sess, s.id)
	close(s.done)
	close(s.in)
	s.setErr(errSessionClosed)
	if len(c.sess) == 0 && c.mux && c.IdleTimeout > 0 {
		if c.idleT == nil {
			// create idle timer that closes the connection when triggered
			c.idleT = time.AfterFunc(c.IdleTimeout, c.close)
		} else {
			c.idleT.Reset(c.IdleTimeout)
		}
	}
}

func (c *conn) cleanup() {
	// close connection done channel before session done channel
	c.close()
	for _, s := range c.sess {
		close(s.done)
		close(s.in)
	}
	err := c.nc.Close()
	if err != nil {
		c.log(err)
	}
	if c.idleT != nil {
		c.idleT.Stop()
	}
}

// serve a TACACS+ connection.
// serve multiplexes incoming packets, session create and session close requests.
func (c *conn) serve() {
	go c.readLoop()
	go c.writeLoop()
	defer c.cleanup()

	for {
		select {
		case p := <-c.rc:
			// process incoming packet
			c.processPacket(p)
		case s := <-c.sessClose:
			// session close request
			c.closeSession(s)
		case sr := <-c.sessReq:
			// new session request
			c.newSession(sr)
		case <-c.done:
			// close connection
			return
		}
		// close non-mux connections with no sessions
		if len(c.sess) == 0 && !c.mux {
			return
		}
	}
}

func newConn(nc net.Conn, h func(*session), cfg ConnConfig) *conn {
	c := &conn{
		nc:         nc,
		mux:        cfg.LegacyMux,             // For LegacyMux allow multiplexing regardless of header flags.
		checkMux:   !cfg.LegacyMux && cfg.Mux, // For (draft) Mux check the first packet for the single-connection flag.
		handle:     h,
		ConnConfig: cfg,
	}
	if c.handle == nil {
		// client connection
		c.sessReq = make(chan sessRequest)
		c.parity = 1
		c.handle = func(s *session) {
			_, err := s.readPacket(context.Background())
			if err != nil {
				c.log(err)
			}
		}
	}
	c.sessClose = make(chan *session)
	c.rc = make(chan []byte)
	c.wc = make(chan writeRequest)
	c.done = make(chan struct{})
	c.sess = make(map[uint32]*session)

	return c
}
