package tacplus

import (
	"context"
	"errors"
	"net"
	"sync"
)

// ClientAuthenSession is a TACACS+ client authentication session.
type ClientAuthenSession struct {
	s *session
}

// Close closes the client authentication session.
func (c *ClientAuthenSession) Close() {
	c.s.close()
}

// Abort sends a message back to the server aborting the session with the supplied reason.
func (c *ClientAuthenSession) Abort(ctx context.Context, reason string) error {
	err := c.s.writePacket(ctx, &authenContinue{Abort: true, Data: []byte(reason)})
	c.s.close()
	return err
}

// Continue is used to send msg in response to a previous AuthenReply.
// A new AuthenReply or error is returned.
func (c *ClientAuthenSession) Continue(ctx context.Context, msg string) (*AuthenReply, error) {
	// sequence number too large to continue
	if c.s.seqNo() >= 0xfe {
		_ = c.Abort(ctx, "")
		return nil, errors.New("session aborted, too many packets")
	}

	rep := new(AuthenReply)
	err := c.s.writePacket(ctx, &authenContinue{UserMsg: msg})
	if err == nil {
		err = c.s.readPacket(ctx, rep)
	}
	if err != nil {
		c.s.close()
		return nil, err
	}
	if rep.last() {
		c.s.close()
	}
	return rep, nil
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

func (c *Client) newSession(ctx context.Context, ver, t uint8) (*session, error) {
	if c.ConnConfig.Mux {
		// try to use existing cached connection
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			if s, _ := conn.newClientSession(ctx, ver, t); s != nil {
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

	s, err := conn.newClientSession(ctx, ver, t)
	if err != nil {
		conn.close()
		return nil, err
	}
	if c.ConnConfig.Mux {
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

// SendAcctRequest sends an AcctRequest to the server returning an AcctReply or error.
func (c *Client) SendAcctRequest(ctx context.Context, req *AcctRequest) (*AcctReply, error) {
	s, err := c.newSession(ctx, verDefault, sessTypeAcct)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err = s.writePacket(ctx, req); err == nil {
		rep := new(AcctReply)
		if err = s.readPacket(ctx, rep); err == nil {
			return rep, nil
		}
	}
	return nil, err
}

// SendAuthorRequest sends an AuthorRequest to the server returning an AuthorResponse or error.
func (c *Client) SendAuthorRequest(ctx context.Context, req *AuthorRequest) (*AuthorResponse, error) {
	s, err := c.newSession(ctx, verDefault, sessTypeAuthor)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err = s.writePacket(ctx, req); err == nil {
		resp := new(AuthorResponse)
		if err = s.readPacket(ctx, resp); err == nil {
			return resp, nil
		}
	}
	return nil, err
}

// SendAuthenStart sends an AuthenStart to the server returning an AuthenReply and
// optional ClientAuthenSession or an error. If ClientAuthenSession is set it should be
// used to complete the current interactive authentication session.
func (c *Client) SendAuthenStart(ctx context.Context, as *AuthenStart) (*AuthenReply, *ClientAuthenSession, error) {
	s, err := c.newSession(ctx, as.version(), sessTypeAuthen)
	if err != nil {
		return nil, nil, err
	}
	if err = s.writePacket(ctx, as); err == nil {
		rep := new(AuthenReply)
		if err = s.readPacket(ctx, rep); err == nil {
			if rep.last() {
				s.close()
				return rep, nil, nil
			}
			return rep, &ClientAuthenSession{s: s}, nil
		}
	}
	s.close()
	return nil, nil, err
}
