package tacplus

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

// ServerSession is a TACACS+ Server Session.
type ServerSession struct {
	*session
	p []byte
}

// Log output using the connections ConnConfig Log function.
func (s *ServerSession) Log(v ...interface{}) {
	s.c.log(v...)
}

func (s *ServerSession) close() {
	s.p = nil
	s.session.close()
}

func (s *ServerSession) writePacket(ctx context.Context, p []byte) error {
	if p[hdrSeqNo] == 1 {
		// Set single connect header flag in the first reply packet for the session.
		// Set it even in LegacyMux to allow normal Mux client connections to multiplex.
		if s.c.Mux || s.c.LegacyMux {
			p[hdrFlags] &= hdrFlagSingleConnect
		} else {
			p[hdrFlags] = 0
		}
	}
	return s.session.writePacket(ctx, p)
}

func (s *ServerSession) sendError(ctx context.Context, err error) {
	if s.p == nil {
		return
	}
	msg := err.Error()
	if len(msg) > maxUint16 {
		msg = msg[:maxUint16]
	}
	p := s.p[:hdrLen]
	switch p[hdrType] {
	case sessTypeAuthen:
		r := AuthenReply{Status: AuthenStatusError, ServerMsg: msg}
		p, _ = r.marshal(p)
	case sessTypeAuthor:
		r := AuthorResponse{Status: AuthorStatusError, ServerMsg: msg}
		p, _ = r.marshal(p)
	case sessTypeAcct:
		r := AcctReply{Status: AcctStatusError, ServerMsg: msg}
		p, _ = r.marshal(p)
	}
	if err = s.writePacket(ctx, p); err != nil {
		s.c.log(err)
	}
	s.close()
}

func (s *ServerSession) sendReply(ctx context.Context, r *AuthenReply) (*AuthenContinue, error) {
	if s.p == nil {
		return nil, errSessionClosed
	}
	//if s.seq > 0xfb {
	//	return nil errors.New("operation will cause sequence number to overlap")
	//}
	p, err := r.marshal(s.p[:hdrLen])
	if err != nil {
		return nil, err
	}
	err = s.writePacket(ctx, p)
	if err != nil {
		s.close()
		return nil, err
	}
	s.p, err = s.readPacket(ctx)
	if err != nil {
		s.sendError(ctx, err)
		return nil, err
	}
	c := new(AuthenContinue)
	err = c.unmarshal(s.p[hdrLen:])
	if err != nil {
		s.sendError(ctx, err)
		return nil, err
	}
	return c, nil
}

// GetData requests the TACACS+ client prompt the user for data with the given message.
// If noEcho is set the client will not echo the users response as it is entered.
func (s *ServerSession) GetData(ctx context.Context, message string, noEcho bool) (*AuthenContinue, error) {
	r := &AuthenReply{Status: AuthenStatusGetData, ServerMsg: message, NoEcho: noEcho}
	return s.sendReply(ctx, r)
}

// GetUser requests the TACACS+ client prompt the user for a username with the given message.
func (s *ServerSession) GetUser(ctx context.Context, message string) (*AuthenContinue, error) {
	r := &AuthenReply{Status: AuthenStatusGetUser, ServerMsg: message}
	return s.sendReply(ctx, r)
}

// GetPass requests the TACACS+ client prompt the user for a password with the given message.
func (s *ServerSession) GetPass(ctx context.Context, message string) (*AuthenContinue, error) {
	r := &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: message, NoEcho: true}
	return s.sendReply(ctx, r)
}

// RemoteAddr returns the remote network address (NAS IP Address) for the session.
func (s *ServerSession) RemoteAddr() net.Addr {
	return s.session.c.nc.RemoteAddr()
}

// LocalAddr returns the local network address for the session.
func (s *ServerSession) LocalAddr() net.Addr {
	return s.session.c.nc.LocalAddr()
}

// A RequestHandler is used for processing the three different types of TACACS+ requests.
//
// Each handle function takes a context and a request/start packet and returns a reply/response
// packet to be sent back to the client. A nil reply will close the session with no reply packet
// being sent. The supplied context is canceled if the underlying TACACS+ session or connection
// is closed.
//
// HandleAuthenStart processes an authentication start, returning an optional reply.
// The ServerSession can be used by interactive sessions to prompt the user for more
// information before the final reply is returned.
//
// HandleAuthorRequest processes an authorization request, returning an optional response.
//
// HandleAcctRequest processes an accounting request, returning an optional reply.
type RequestHandler interface {
	HandleAuthenStart(ctx context.Context, a *AuthenStart, s *ServerSession) *AuthenReply
	HandleAuthorRequest(ctx context.Context, a *AuthorRequest) *AuthorResponse
	HandleAcctRequest(ctx context.Context, a *AcctRequest) *AcctReply
}

// A ServerConnHandler serves TACACS+ requests on a network connection.
type ServerConnHandler struct {
	Handler    RequestHandler // TACACS+ request handler
	ConnConfig ConnConfig     // TACACS+ connection config
}

func (h *ServerConnHandler) handleAuthenStart(ctx context.Context, s *ServerSession) ([]byte, error) {
	as := new(AuthenStart)
	err := as.unmarshal(s.p[hdrLen:])
	if err != nil {
		return s.p, err
	}
	v := as.version()
	if s.p[hdrVer] != v {
		err = fmt.Errorf("unsupported authentication minor version %d", s.p[hdrVer]&0xf)
		s.p[hdrVer] = v
		return s.p, err
	}
	reply := h.Handler.HandleAuthenStart(s.context(), as, s)
	if reply == nil {
		return nil, nil
	}
	s.p, err = reply.marshal(s.p[:hdrLen])
	if err != nil {
		err = fmt.Errorf("Bad Server AuthenReply: %s", err)
	}
	return s.p, err
}

func (h *ServerConnHandler) handleAuthorRequest(ctx context.Context, p []byte) ([]byte, error) {
	ar := new(AuthorRequest)
	err := ar.unmarshal(p[hdrLen:])
	if err != nil {
		return p, err
	}
	if p[hdrVer] != verDefault {
		err = fmt.Errorf("unsupported authorization minor version %d", p[hdrVer]&0xf)
		p[hdrVer] = verDefault
		return p, err
	}
	reply := h.Handler.HandleAuthorRequest(ctx, ar)
	if reply == nil {
		return nil, nil
	}
	p, err = reply.marshal(p[:hdrLen])
	if err != nil {
		err = fmt.Errorf("Bad Server AuthorResponse: %s", err)
	}
	return p, err
}

func (h *ServerConnHandler) handleAcctRequest(ctx context.Context, p []byte) ([]byte, error) {
	ar := new(AcctRequest)
	err := ar.unmarshal(p[hdrLen:])
	if err != nil {
		return p, err
	}
	if p[hdrVer] != verDefault {
		err = fmt.Errorf("unsupported accounting minor version %d", p[hdrVer]&0xf)
		p[hdrVer] = verDefault
		return p, err
	}
	reply := h.Handler.HandleAcctRequest(ctx, ar)
	if reply == nil {
		return nil, nil
	}
	p, err = reply.marshal(p[:hdrLen])
	if err != nil {
		err = fmt.Errorf("Bad Server AcctReply: %s", err)
	}
	return p, err
}

func (h *ServerConnHandler) serveSession(sess *session) {
	var err error

	s := &ServerSession{sess, nil}
	defer s.close()

	ctx := context.Background()
	s.p, err = s.readPacket(ctx)
	if err != nil {
		s.c.log(err)
		s.sendError(ctx, err)
		return
	}

	switch s.p[hdrType] {
	case sessTypeAuthen:
		s.p, err = h.handleAuthenStart(s.context(), s)
	case sessTypeAuthor:
		s.p, err = h.handleAuthorRequest(s.context(), s.p)
	case sessTypeAcct:
		s.p, err = h.handleAcctRequest(s.context(), s.p)
	default:
		err = fmt.Errorf("invalid session type %d", s.p[hdrType])
	}

	if err != nil {
		s.c.log(err)
		s.sendError(ctx, err)
		return
	}

	if s.p != nil {
		err = s.writePacket(ctx, s.p)
		if err != nil {
			s.c.log(err)
		}
	}
}

// Serve processes incoming TACACS+ requests on the network connection nc.
// A nil ServerConnHandler will close the connection without any processing.
func (h *ServerConnHandler) Serve(nc net.Conn) {
	var c *conn
	if h != nil {
		c = newConn(nc, h.serveSession, h.ConnConfig)
		c.serve()
	} else if err := nc.Close(); err != nil {
		c.log(err)
	}
}

// Server is a generic network server.
type Server struct {
	// ServeConn is run on incoming network connections. It must close the
	// supplied net.Conn when finsihed with it.
	ServeConn func(net.Conn)

	// Optional function to log errors. If not defined log.Print will be used.
	Log func(...interface{})
}

// Serve accepts incoming connections on the net.Listener l, creating a new
// goroutine running ServeConn on the connection.
func (srv *Server) Serve(l net.Listener) error {
	logErr := srv.Log
	if logErr == nil {
		logErr = log.Print
	}

	var tempDelay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				logErr("Accept error: ", err, " retrying in ", tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			_ = l.Close() // ignore error, can only return one
			return err
		}
		tempDelay = 0
		go srv.ServeConn(c)
	}
}
