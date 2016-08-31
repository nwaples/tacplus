package tacplus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

// ServerSession is a TACACS+ Server Session.
type ServerSession struct {
	*session
}

// Log output using the connections ConnConfig Log function.
func (s *ServerSession) Log(v ...interface{}) {
	s.c.log(v...)
}

func (s *ServerSession) sendReply(ctx context.Context, r *AuthenReply) (string, error) {
	//if s.seq > 0xfb {
	//	return "", errors.New("operation will cause sequence number to overlap")
	//}
	err := s.writePacket(ctx, r)
	if err != nil {
		return "", err
	}
	c := new(authenContinue)
	err = s.readPacket(ctx, c)
	switch err {
	case nil:
		if c.Abort {
			s.close()
			return "", errors.New("Session Aborted: " + string(c.Data))
		}
		return c.UserMsg, nil
	case errSessionClosed, context.Canceled, context.DeadlineExceeded:
	default:
		r := &AuthenReply{Status: AuthenStatusError, ServerMsg: err.Error()}
		if werr := s.writePacket(ctx, r); werr != nil {
			s.c.log(werr)
		}
	}
	s.close()
	return "", err
}

func (s *ServerSession) readPacket(ctx context.Context, p packet) error {
	data, err := s.session.readPacket(ctx)
	if err != nil {
		return err
	}
	return p.unmarshal(data[hdrLen:])
}

func (s *ServerSession) writePacket(ctx context.Context, p packet) error {
	data, err := p.marshal(make([]byte, hdrLen, 1024))
	if err != nil {
		return err
	}
	return s.session.writePacket(ctx, data)
}

// GetData requests the TACACS+ client prompt the user for data with the given message.
// If noEcho is set the client will not echo the users response as it is entered.
func (s *ServerSession) GetData(ctx context.Context, message string, noEcho bool) (string, error) {
	r := &AuthenReply{Status: AuthenStatusGetData, ServerMsg: message, NoEcho: noEcho}
	return s.sendReply(ctx, r)
}

// GetUser requests the TACACS+ client prompt the user for a username with the given message.
func (s *ServerSession) GetUser(ctx context.Context, message string) (string, error) {
	r := &AuthenReply{Status: AuthenStatusGetUser, ServerMsg: message}
	return s.sendReply(ctx, r)
}

// GetPass requests the TACACS+ client prompt the user for a password with the given message.
func (s *ServerSession) GetPass(ctx context.Context, message string) (string, error) {
	r := &AuthenReply{Status: AuthenStatusGetPass, ServerMsg: message, NoEcho: true}
	return s.sendReply(ctx, r)
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

func (h *ServerConnHandler) serveAuthenSession(s *ServerSession) (packet, error) {
	as := new(AuthenStart)
	err := s.readPacket(context.Background(), as)
	if s.version != as.version() {
		err = fmt.Errorf("unsupported authentication minor version %d", s.version&0xf)
	}
	if err != nil {
		return &AuthenReply{Status: AuthenStatusError, ServerMsg: err.Error()}, err
	}
	if reply := h.Handler.HandleAuthenStart(s.context(), as, s); reply != nil {
		return reply, nil
	}
	return nil, nil
}

func (h *ServerConnHandler) serveAuthorSession(s *ServerSession) (packet, error) {
	ar := new(AuthorRequest)
	err := s.readPacket(context.Background(), ar)
	if s.version != verDefault {
		err = fmt.Errorf("unsupported authorization minor version %d", s.version&0xf)
	}
	if err != nil {
		return &AuthorResponse{Status: AuthorStatusError, ServerMsg: err.Error()}, err
	}
	if reply := h.Handler.HandleAuthorRequest(s.context(), ar); reply != nil {
		return reply, nil
	}
	return nil, nil
}

func (h *ServerConnHandler) serveAcctSession(s *ServerSession) (packet, error) {
	ar := new(AcctRequest)
	err := s.readPacket(context.Background(), ar)
	if s.version != verDefault {
		err = fmt.Errorf("unsupported accounting minor version %d", s.version&0xf)
	}
	if err != nil {
		return &AcctReply{Status: AcctStatusError, ServerMsg: err.Error()}, err
	}
	if reply := h.Handler.HandleAcctRequest(s.context(), ar); reply != nil {
		return reply, nil
	}
	return nil, nil
}

func (h *ServerConnHandler) serveSession(sess *session) {
	s := &ServerSession{sess}
	defer s.close()

	var reply packet
	var err error
	switch s.sessType {
	case sessTypeAuthen:
		reply, err = h.serveAuthenSession(s)
	case sessTypeAuthor:
		reply, err = h.serveAuthorSession(s)
	case sessTypeAcct:
		reply, err = h.serveAcctSession(s)
	default:
		// error reply for an unknown session type is just an empty packet
		reply = new(nullPacket)
		if err = s.readPacket(context.Background(), reply); err == nil {
			err = fmt.Errorf("invalid session type %d", s.sessType)
		}
	}
	if err != nil {
		s.c.log(err)
	}
	if reply != nil {
		err = s.writePacket(context.Background(), reply)
		if err != nil {
			s.c.log(err)
		}
	}
}

// Serve processes incoming TACACS+ requests on the network connection nc.
// A nil ServerConnHandler will close the connection without any processing.
func (h *ServerConnHandler) Serve(nc net.Conn) {
	if h != nil {
		c := newConn(nc, h.serveSession, h.ConnConfig)
		c.serve()
	}
	nc.Close()
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

	defer l.Close()
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
			return err
		}
		tempDelay = 0
		go srv.ServeConn(c)
	}
}
