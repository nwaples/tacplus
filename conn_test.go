package tacplus

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

var payloadTestsTypes = []byte {
	sessTypeAuthen,
	sessTypeAuthor,
	sessTypeAcct,
}

var payloadTests = []packet{
	&AuthenStart{
		Action:        AuthenActionSendAuth,
		PrivLvl:       23,
		AuthenType:    AuthenTypeARAP,
		AuthenService: AuthenServiceX25,
		User:          "fred",
		Port:          "tty00",
		RemAddr:       "10.1.2.3",
		Data:          []byte{0, 1, 2, 3, 0, 1},
	},
	&AuthorRequest{
		AuthenMethod:  AuthenMethodKRB4,
		PrivLvl:       99,
		AuthenType:    AuthenTypeMSCHAP,
		AuthenService: AuthenServiceFWProxy,
		User:          "fred",
		Port:          "tty00",
		RemAddr:       "10.0.0.1",
		Arg:           []string{"protocol=ip", "timeout=1"},
	},
	&AcctRequest{
		Flags:         AcctFlagMore,
		AuthenMethod:  AuthenMethodEnable,
		PrivLvl:       15,
		AuthenType:    AuthenTypeCHAP,
		AuthenService: AuthenServicePT,
		User:          "joe",
		Port:          "port23",
		RemAddr:       "192.168.1.1",
		Arg:           []string{"a=b", "c=d"},
	},
}

func connTestLog(v ...interface{}) {
	if len(v) == 0 {
		return
	}
	err, ok := v[0].(error)
	if !ok {
		err = errors.New(fmt.Sprint(v...))
	}
	if err != nil {
		fmt.Println(err)
	}
}

func TestCheckPayload(t *testing.T) {
	for index, p := range payloadTests {
		tp := reflect.Indirect(reflect.ValueOf(p)).Type() // get type
		b := make([]byte, 128)
		b, err := p.marshal(b[:hdrLen])
		if err != nil {
			t.Error("marshal of", tp.Name(), p, "failed:", err)
			continue
		}
		binary.BigEndian.PutUint32(b[hdrBodyLen:], uint32(len(b)-hdrLen))
		b[hdrType] = payloadTestsTypes[index]
		// Encrypt then decret using the same secret
		crypt(b, []byte("secret"))
		crypt(b, []byte("secret"))
		c := ConnConfig {
			Log: connTestLog,
		}
		err = checkPayload(b, &c)
		if err != nil {
			t.Error("checkPayload of", tp.Name(), p, "failed:", err)
		}
		// Encrypt then decret using the wrong secret
		crypt(b, []byte("secret"))
		crypt(b, []byte("wrong_secret"))
		err = checkPayload(b, &c)
		if err == nil {
			t.Error("checkPayload should have failed ", tp.Name(), p, ":", err)
		}
	}
}

func TestReadPacket(t *testing.T) {
	for index, p := range payloadTests {
		tp := reflect.Indirect(reflect.ValueOf(p)).Type() // get type
		b := make([]byte, 128)
		b, err := p.marshal(b[:hdrLen])
		if err != nil {
			t.Error("marshal of", tp.Name(), p, "failed:", err)
			continue
		}
		binary.BigEndian.PutUint32(b[hdrBodyLen:], uint32(len(b)-hdrLen))
		b[hdrType] = payloadTestsTypes[index]
		b[hdrSeqNo] = 1
		ctx := context.Background()
		{
			crypt(b, []byte("secret"))
			c := conn {
				ConnConfig: ConnConfig {
					Log: connTestLog,
					RotatingSecrets: [][]byte{[]byte("secret"), []byte("wrong_secret")},
				},
			}
			s := newSession(&c, 42)
			// Write the packet to the receive channel of session
			s.in <- b
			b, err = s.readPacket(ctx)
			if err != nil {
				t.Error("readPacket of", tp.Name(), p, "failed:", err)
			}
			if s.rotatingSecretIndex != 0 {
				t.Error("readPacket uses wrong index", s.rotatingSecretIndex)
			}
		}

		// secret not in index 0
		{
			crypt(b, []byte("secret"))
			c := conn {
				ConnConfig: ConnConfig {
					Log: connTestLog,
					RotatingSecrets: [][]byte{[]byte("wrong_secret"), []byte("secret")},
				},
			}
			s := newSession(&c, 42)
			// Write the packet to the receive channel of session
			s.in <- b
			b, err = s.readPacket(ctx)
			if err != nil {
				t.Error("readPacket of", tp.Name(), p, "failed:", err)
			}
			if s.rotatingSecretIndex != 1 {
				t.Error("readPacket uses wrong index", s.rotatingSecretIndex)
			}
		}
		// secret not found
		{
			crypt(b, []byte("secret"))
			c := conn {
				ConnConfig: ConnConfig {
					Log: connTestLog,
					RotatingSecrets: [][]byte{[]byte("wrong_secret")},
				},
			}
			s := newSession(&c, 42)
			// Write the packet to the receive channel of session
			s.in <- b
			b, err = s.readPacket(ctx)
			if err == nil {
				t.Error("readPacket of", tp.Name(), p, "should have failed:", err)
			}
			if s.rotatingSecretIndex != -1 {
				t.Error("readPacket shouldn't have updated index", s.rotatingSecretIndex)
			}
		}
	}
}

func TestWritePacket(t *testing.T) {
	b := make([]byte, 128)
	b[hdrSeqNo + 1] = 1
	b[hdrSeqNo + 2] = 2
	ctx := context.Background()
	c := conn {
		ConnConfig: ConnConfig {
			Log: connTestLog,
			RotatingSecrets: [][]byte{[]byte("wrong_secret"), []byte("secret")},
		},
		wc : make(chan writeRequest),
	}
	s := newSession(&c, 42)

	err := s.writePacket(ctx, b)
	if err == nil {
		t.Error("writePacket of", b, " should have failed:", err)
	}

	// Set up a valid rottaing secret index
	s.rotatingSecretIndex = 1 
	// Create a null function for packet write
	go func (c *conn) {
		for {
			select {
			case req := <-c.wc:
				req.ec <- nil
			}
		}
	} (&c)
	err = s.writePacket(ctx, b)
	if err != nil {
		t.Error("writePacket of", b, " failed:", err)
	}
	// Verify that the packet can be decrypted
	crypt(b, []byte("secret"))
	// Don't try to check the headers
	if b[hdrSeqNo + 1] != 1 || b[hdrSeqNo + 2] != 2 {
		t.Error("Failed to decrypt packet")
	}
}
