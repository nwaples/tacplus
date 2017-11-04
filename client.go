package tacplus

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// ClientSession is a TACACS+ client session.
type ClientSession struct {
	*session
	p []byte
}

// Close closes the client session.
func (c *ClientSession) Close() {
	c.p = nil
	c.close()
}

// Abort sends a message back to the server aborting the session with the supplied reason.
func (c *ClientSession) Abort(ctx context.Context, reason string) error {
	if len(reason) > maxUint16 {
		reason = reason[:maxUint16]
	}
	err := c.sendRequest(ctx, &AuthenContinue{Abort: true, Message: reason}, nil)
	c.Close()
	return err
}

// Continue is used to send msg in response to a previous AuthenReply.
// A new AuthenReply or error is returned.
func (c *ClientSession) Continue(ctx context.Context, msg string) (*AuthenReply, error) {
	// sequence number too large to continue
	if c.seq >= 0xfe {
		_ = c.Abort(ctx, "")
		return nil, errors.New("session aborted, too many packets")
	}

	rep := new(AuthenReply)
	if err := c.sendRequest(ctx, &AuthenContinue{Message: msg}, rep); err != nil {
		c.Close()
		return nil, err
	}
	if rep.last() {
		c.Close()
	}
	return rep, nil
}

func (c *ClientSession) sendRequest(ctx context.Context, req, rep packet) error {
	if c.p == nil {
		return errSessionClosed
	}
	p, err := req.marshal(c.p[:hdrLen])
	if err != nil {
		return err
	}
	err = c.writePacket(ctx, p)
	if err != nil || rep == nil {
		return err
	}
	c.p, err = c.readPacket(ctx)
	if err == nil {
		err = rep.unmarshal(c.p[hdrLen:])
	}
	return err
}

// Client is a TACACS+ client that connects to a single TACACS+ server.
//
// If the Client's ConnConfig enables session multiplexing, the client will
// cache a single open connection for this purpose.
type Client struct {
	Addr       string     // TCP address of tacacs server.
	ConnConfig ConnConfig // TACACS+ connection configuration.

	// Optional DialContext function used to create the network connection.
	DialContext func(ctx context.Context, net, addr string) (net.Conn, error)

	mu   sync.Mutex // protects access to conn
	conn *conn      // current cached mux connection
}

// Close closes the cached connection.
func (c *Client) Close() {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.close()
	}
}

var zeroDialer net.Dialer

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.DialContext != nil {
		return c.DialContext(ctx, "tcp", c.Addr)
	}
	return zeroDialer.DialContext(ctx, "tcp", c.Addr)
}

func (c *Client) newSession(ctx context.Context) (*session, error) {
	mux := c.ConnConfig.Mux || c.ConnConfig.LegacyMux
	if mux {
		// try to use existing cached connection
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			if s, _ := conn.newClientSession(ctx); s != nil {
				return s, nil
			}
		}
	}

	// create new connection
	nc, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	conn := newConn(nc, nil, c.ConnConfig)
	go conn.serve()

	s, err := conn.newClientSession(ctx)
	if err != nil {
		conn.close()
		return nil, err
	}
	if mux {
		// attempt to cache multiplexed connection
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.conn == nil {
			// cache this connection
			c.conn = conn
			go func() {
				// clear cached reference when conn closes
				<-conn.done
				c.mu.Lock()
				c.conn = nil
				c.mu.Unlock()
			}()
		} else {
			// already cached one connection, so create goroutine
			// that closes connection when session is closed so
			// we don't leak idle connections.
			go func() {
				<-s.done
				conn.close()
			}()
		}
	}
	return s, nil
}

func (c *Client) startSession(ctx context.Context, ver, t uint8, req, rep packet) (*ClientSession, error) {
	s, err := c.newSession(ctx)
	if err != nil {
		return nil, err
	}
	p := make([]byte, 1024)
	p[hdrVer] = ver
	p[hdrType] = t
	if s.c.Mux && !s.c.LegacyMux {
		p[hdrFlags] = hdrFlagSingleConnect
	}
	binary.BigEndian.PutUint32(p[hdrID:], s.id)
	cs := &ClientSession{s, p}
	if err = cs.sendRequest(ctx, req, rep); err != nil {
		cs.close()
		return nil, err
	}
	return cs, nil
}

// SendAcctRequest sends an AcctRequest to the server returning an AcctReply or error.
func (c *Client) SendAcctRequest(ctx context.Context, req *AcctRequest) (*AcctReply, error) {
	rep := new(AcctReply)
	s, err := c.startSession(ctx, verDefault, sessTypeAcct, req, rep)
	if err != nil {
		return nil, err
	}
	s.close()
	return rep, nil
}

// SendAuthorRequest sends an AuthorRequest to the server returning an AuthorResponse or error.
func (c *Client) SendAuthorRequest(ctx context.Context, req *AuthorRequest) (*AuthorResponse, error) {
	resp := new(AuthorResponse)
	s, err := c.startSession(ctx, verDefault, sessTypeAuthor, req, resp)
	if err != nil {
		return nil, err
	}
	s.close()
	return resp, nil
}

// SendAuthenStart sends an AuthenStart to the server returning an AuthenReply and
// optional ClientSession or an error. If ClientSession is set it should be
// used to complete the current interactive authentication session.
func (c *Client) SendAuthenStart(ctx context.Context, as *AuthenStart) (*AuthenReply, *ClientSession, error) {
	rep := new(AuthenReply)
	s, err := c.startSession(ctx, as.version(), sessTypeAuthen, as, rep)
	if err != nil {
		return nil, nil, err
	}
	if rep.last() {
		s.close()
		return rep, nil, nil
	}
	return rep, s, nil
}
