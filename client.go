package tacplus

import (
	"context"
	"errors"
	"net"
	"sync"
)

// ClientSession is a TACACS+ client session.
type ClientSession struct {
	*session
}

// Close closes the client session.
func (c *ClientSession) Close() {
	c.close()
}

// Abort sends a message back to the server aborting the session with the supplied reason.
func (c *ClientSession) Abort(ctx context.Context, reason string) error {
	if len(reason) > maxUint16 {
		reason = reason[:maxUint16]
	}
	err := c.sendRequest(ctx, &authenContinue{Abort: true, Data: []byte(reason)}, nil)
	c.close()
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
	if err := c.sendRequest(ctx, &authenContinue{UserMsg: msg}, rep); err != nil {
		c.close()
		return nil, err
	}
	if rep.last() {
		c.close()
	}
	return rep, nil
}

func (c *ClientSession) sendRequest(ctx context.Context, req, rep packet) error {
	err := c.writePacket(ctx, req)
	if err != nil || rep == nil {
		return err
	}
	return c.readPacket(ctx, rep)
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

func (c *Client) startSession(ctx context.Context, ver, t uint8, req, rep packet) (*ClientSession, error) {
	s, err := c.newSession(ctx, ver, t)
	if err != nil {
		return nil, err
	}
	cs := &ClientSession{s}
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
