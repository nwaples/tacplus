package tacplus

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestClientDialContext(t *testing.T) {
	l, c, err := newTestInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	defer c.Close()

	ch := make(chan struct{}) // closed when DialContext is called
	c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		close(ch)
		d := new(net.Dialer)
		return d.DialContext(ctx, network, addr)
	}

	reply, _, err := c.SendAuthenStart(context.Background(), testAuthStart)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-ch:
	default:
		t.Fatalf("DialContext not called")
	}
	if reply.Status != AuthenStatusGetUser {
		t.Fatalf("want status %v: %v", AuthenStatusGetUser, reply.Status)
	}
	if err = l.err(); err != nil {
		t.Fatal("unexpected server/client error:", err)
	}
}

func TestClientSession(t *testing.T) {
	l, c, err := newTestInstance(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	defer c.Close()

	var users = []struct {
		name, pass string
		sess       *ClientSession
		status     uint8
	}{
		{"fred", "password123", nil, AuthenStatusFail},
		{"user", "password321", nil, AuthenStatusFail},
		{"user", "password123", nil, AuthenStatusPass},
	}

	ctx := context.Background()
	for i := range users {
		_, users[i].sess, err = c.SendAuthenStart(ctx, testAuthStart)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		_, err = u.sess.Continue(ctx, u.name)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		var r *AuthenReply
		r, err = u.sess.Continue(ctx, u.pass)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != u.status {
			t.Fatalf("user=%s pass=%s wanted status: %d, got %d", u.name, u.pass, r.Status, u.status)
		}
	}

	if err = l.err(); err != nil {
		t.Fatal("unexpected server/client error:", err)
	}
}

func TestClientRequestTimeout(t *testing.T) {
	l, c, err := newTestInstance(&delayHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*timeScale)
	_, err = c.SendAcctRequest(ctx, testAcctReq)
	cancel()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 1*timeScale)
	_, err = c.SendAcctRequest(ctx, testAcctReq)
	cancel()
	if err != context.DeadlineExceeded {
		t.Fatal(context.DeadlineExceeded, "!=", err)
	}
	if err = l.err(); err != nil {
		t.Fatal("unexpected server/client error:", err)
	}
}

func TestClientIdleTimeout(t *testing.T) {
	l, c, err := newTestInstance(&delayHandler)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	defer c.Close()
	c.ConnConfig.IdleTimeout = 2 * timeScale

	var timeoutTests = []struct {
		sleep time.Duration
		count int
	}{
		{0 * timeScale, 1},
		{1 * timeScale, 1},
		{3 * timeScale, 2},
		{1 * timeScale, 2},
		{3 * timeScale, 3},
	}

	ctx := context.Background()
	for i, test := range timeoutTests {
		time.Sleep(test.sleep)
		if _, err = c.SendAcctRequest(ctx, testAcctReq); err != nil {
			t.Fatal(err)
		}
		if n := l.connCount(); n != test.count {
			t.Fatalf("case %d: expected count %d, got %d", i, test.count, n)
		}
	}
	if err = l.err(); err != nil {
		t.Fatal("unexpected server/client error:", err)
	}
}
