package tacplus

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	testSecret = []byte("shared secret")

	testHandler = ServerConnHandler{
		Handler: &testRequestHandler{
			"user": {
				password: "password123",
				args:     []string{"priv-lvl=5"},
			},
			"fred": {
				password: "@password@",
				args:     []string{"priv-lvl=1", "timeout=5"},
			},
		},
		ConnConfig: ConnConfig{
			Secret: testSecret,
			Mux:    true,
		},
	}

	delayHandler = ServerConnHandler{
		Handler:    &delayedRequestHandler{2 * timeScale, testHandler.Handler},
		ConnConfig: testHandler.ConnConfig,
	}

	testAcctReq = &AcctRequest{
		Flags:         AcctFlagStart,
		AuthenMethod:  AuthenMethodNone,
		PrivLvl:       1,
		AuthenType:    AuthenTypeCHAP,
		AuthenService: AuthenServicePPP,
		User:          "fred",
		Port:          "123",
		RemAddr:       "1.2.3.4",
		Arg:           []string{"variable=something", "arg2=", "arg3=abcd"},
	}

	testAuthorReq = &AuthorRequest{
		AuthenMethod:  AuthenMethodLine,
		PrivLvl:       1,
		AuthenType:    AuthenTypeASCII,
		AuthenService: AuthenServiceLogin,
		User:          "user",
		Port:          "321",
		RemAddr:       "4.3.2.1",
		Arg:           []string{"variable=somethingelse", "arg2=123"},
	}

	testAuthStart = &AuthenStart{
		Action:        AuthenActionLogin,
		AuthenType:    AuthenTypeASCII,
		AuthenService: AuthenServiceLogin,
		PrivLvl:       1,
		Port:          "tty123",
		RemAddr:       "1.2.3.4",
	}

	timeScale = 20 * time.Millisecond
)

type testRequestHandler map[string]struct {
	password string
	args     []string
}

func (t testRequestHandler) HandleAuthenStart(ctx context.Context, a *AuthenStart, s *ServerSession) *AuthenReply {
	user := a.User
	for user == "" {
		c, err := s.GetUser(context.Background(), "Username:")
		if err != nil || c.Abort {
			return nil
		}
		user = c.Message
	}
	if user == "ignore" {
		return nil
	}
	pass := ""
	for pass == "" {
		c, err := s.GetPass(context.Background(), "Password:")
		if err != nil || c.Abort {
			return nil
		}
		pass = c.Message
	}
	if u, ok := t[user]; ok && u.password == pass {
		return &AuthenReply{Status: AuthenStatusPass}
	}
	return &AuthenReply{Status: AuthenStatusFail}
}

func (t testRequestHandler) HandleAuthorRequest(ctx context.Context, a *AuthorRequest) *AuthorResponse {
	if u, ok := t[a.User]; ok {
		return &AuthorResponse{Status: AuthorStatusPassAdd, Arg: u.args}
	}
	if a.User == "ignore" {
		return nil
	}
	return &AuthorResponse{Status: AuthorStatusFail}
}

func (t testRequestHandler) HandleAcctRequest(ctx context.Context, a *AcctRequest) *AcctReply {
	if a.User == "ignore" {
		return nil
	}
	return &AcctReply{Status: AcctStatusSuccess}
}

type delayedRequestHandler struct {
	t time.Duration
	h RequestHandler
}

func (h *delayedRequestHandler) HandleAuthenStart(ctx context.Context, a *AuthenStart, s *ServerSession) *AuthenReply {
	time.Sleep(h.t)
	return h.h.HandleAuthenStart(ctx, a, s)
}

func (h *delayedRequestHandler) HandleAuthorRequest(ctx context.Context, a *AuthorRequest) *AuthorResponse {
	time.Sleep(h.t)
	return h.h.HandleAuthorRequest(ctx, a)
}

func (h *delayedRequestHandler) HandleAcctRequest(ctx context.Context, a *AcctRequest) *AcctReply {
	time.Sleep(h.t)
	return h.h.HandleAcctRequest(ctx, a)
}

type testLog struct {
	l        net.Listener
	mu       sync.Mutex
	connLog  []net.Conn
	errorLog []error
}

func (t *testLog) close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// close all connections if not already closed
	for _, c := range t.connLog {
		_ = c.Close()
	}
	if t.l != nil {
		_ = t.l.Close()
	}
}

func (t *testLog) connCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.connLog)
}

func (t *testLog) log(v ...interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(v) == 0 {
		return
	}
	err, ok := v[0].(error)
	if !ok {
		err = errors.New(fmt.Sprint(v...))
	}
	if err != nil {
		t.errorLog = append(t.errorLog, err)
	}
}

func (t *testLog) err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.errorLog) == 0 {
		return nil
	}
	err := t.errorLog[0]
	t.errorLog = t.errorLog[1:]
	return err
}

func newTestInstance(h *ServerConnHandler) (*testLog, *Client, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	t := &testLog{l: l}
	s := testHandler
	if h != nil {
		s = *h
	}
	s.ConnConfig.Log = t.log

	srv := &Server{
		ServeConn: func(nc net.Conn) {
			t.mu.Lock()
			t.connLog = append(t.connLog, nc)
			t.mu.Unlock()
			s.Serve(nc)
		},
	}
	go func() { t.log(srv.Serve(l)) }()

	c := &Client{
		Addr: l.Addr().String(),
		ConnConfig: ConnConfig{
			Secret: testSecret,
			Mux:    true,
			Log:    t.log,
		},
	}

	return t, c, nil
}

func TestServe(t *testing.T) {
	s, c, err := newTestInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	defer c.Close()

	ctx := context.Background()
	_, sess, err := c.SendAuthenStart(ctx, testAuthStart)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sess.Continue(ctx, "nothing")
	if err != nil {
		t.Fatal(err)
	}
	_, err = sess.Continue(ctx, "nopass")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.SendAcctRequest(ctx, testAcctReq)
	if err != nil {
		t.Fatal(err)
	}

	if err = s.err(); err != nil {
		t.Fatal("unexpected server/client error:", err)
	}
	if cnt := s.connCount(); cnt != 1 {
		t.Fatalf("error output: %d", cnt)
	}
}

func TestEncryption(t *testing.T) {
	s, c, err := newTestInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	defer c.Close()

	ctx := context.Background()
	if _, err = c.SendAcctRequest(ctx, testAcctReq); err != nil {
		t.Fatal(err)
	}
	c.Close()

	c.ConnConfig.Secret = []byte("bad secret")
	if _, err = c.SendAcctRequest(ctx, testAcctReq); err != errBadPacket {
		t.Fatal(err)
	}

	if err := s.err(); err != errBadPacket {
		t.Fatalf("want %v: got %v", errBadPacket, err)
	}
}

func testMux(t *testing.T, cmux, clmux, smux, slmux bool, count int) {
	h := testHandler
	h.ConnConfig.Mux = smux
	h.ConnConfig.LegacyMux = slmux
	s, c, err := newTestInstance(&h)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	defer c.Close()
	c.ConnConfig.Mux = cmux
	c.ConnConfig.LegacyMux = clmux

	ctx := context.Background()
	if _, err = c.SendAcctRequest(ctx, testAcctReq); err != nil {
		t.Error(err)
		return
	}

	// Sleep to allow client connection to close
	time.Sleep(time.Millisecond)

	_, sess, err := c.SendAuthenStart(ctx, testAuthStart)
	if err != nil {
		t.Error(err)
		return
	}

	if _, err = c.SendAuthorRequest(ctx, testAuthorReq); err != nil {
		t.Error(err)
		return
	}

	err = sess.Abort(ctx, "aborted")
	if err != nil {
		t.Error(err)
		return
	}

	if n := s.connCount(); n != count {
		t.Errorf("connection count expected: %d actual: %d", count, n)
	} else if err := s.err(); err != nil {
		t.Error("unexpected server/client error: ", err)
	}
}

func TestConnectionMux(t *testing.T) {
	var muxTests = []struct {
		smux, slmux bool
		cmux, clmux bool
		count       int
	}{
		{false, false, false, false, 3},
		{true, false, false, false, 3},
		{false, true, false, false, 3},
		{true, true, false, false, 3},
		{false, false, true, false, 3},
		{true, false, true, false, 1},
		{false, true, true, false, 1},
		{true, true, true, false, 1},
		{false, false, false, true, 2},
		{true, false, false, true, 2},
		{false, true, false, true, 1},
		{true, true, false, true, 1},
		{false, false, true, true, 2},
		{true, false, true, true, 2},
		{false, true, true, true, 1},
		{true, true, true, true, 1},
	}

	for _, test := range muxTests {
		testMux(t, test.cmux, test.clmux, test.smux, test.slmux, test.count)
	}
}

func TestRequestHandlerNilReturn(t *testing.T) {
	s, c, err := newTestInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	defer c.Close()

	funcs := map[string]func(ctx context.Context) error{
		"SendAcctRequest": func(ctx context.Context) error {
			req := *testAcctReq
			req.User = "ignore"
			_, err := c.SendAcctRequest(ctx, &req)
			return err
		},
		"SendAuthenStart": func(ctx context.Context) error {
			req := *testAuthStart
			req.User = "ignore"
			_, sess, err := c.SendAuthenStart(ctx, &req)
			if sess != nil {
				sess.Close()
			}
			return err
		},
		"SendAuthorRequest": func(ctx context.Context) error {
			req := *testAuthorReq
			req.User = "ignore"
			_, err := c.SendAuthorRequest(ctx, &req)
			return err
		},
	}

	for desc, f := range funcs {
		c.ConnConfig.Mux = true
		c.Close()

		ctx, cancel := context.WithTimeout(context.Background(), timeScale)
		err := f(ctx)
		cancel()
		if err != context.DeadlineExceeded {
			t.Error(desc, "expected:", context.DeadlineExceeded, ", got:", err)
		}
		c.Close()

		ctx, cancel = context.WithTimeout(context.Background(), timeScale)
		c.ConnConfig.Mux = false
		err = f(ctx)
		cancel()
		if err != errSessionClosed {
			t.Error(desc, "expected:", errSessionClosed, ", got:", err)
		}
	}
}
