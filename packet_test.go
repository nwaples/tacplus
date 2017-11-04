package tacplus

import (
	"reflect"
	"testing"
)

var marshalUnmarshalTests = []packet{
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
	&AuthenReply{
		Status:    AuthenStatusFollow,
		NoEcho:    true,
		ServerMsg: "nothing here",
		Data:      []byte{9, 8, 7, 6},
	},
	&AuthenContinue{Abort: false, Message: "message one"},
	&AuthenContinue{Abort: true, Message: "message two"},
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
	&AuthorResponse{
		Status:    AuthorStatusFail,
		Arg:       []string{"idletime=2", "priv_lvl=1"},
		ServerMsg: "server message",
		Data:      "data",
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
	&AcctReply{
		Status:    AcctStatusSuccess,
		ServerMsg: "user log message",
		Data:      "admin log message",
	},
}

func TestPacketMarshalUnmarshal(t *testing.T) {
	for _, p := range marshalUnmarshalTests {
		tp := reflect.Indirect(reflect.ValueOf(p)).Type() // get type
		b, err := p.marshal(nil)
		if err != nil {
			t.Error("marshal of", tp.Name(), p, "failed:", err)
			continue
		}
		p2, _ := reflect.New(tp).Interface().(packet) // create new variable
		err = p2.unmarshal(b)
		if err != nil {
			t.Error("unmarshal of", tp.Name(), p, "failed:", err)
		} else if !reflect.DeepEqual(p, p2) {
			t.Error(p2, "!=", p)
		}
	}
}
