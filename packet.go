package tacplus

import (
	"errors"
	"math"
)

const (
	// Session Types
	sessTypeAuthen = 1
	sessTypeAuthor = 2
	sessTypeAcct   = 3

	authenReplyFlagNoEcho = 0x1

	authenContinueFlagAbort = 0x1
)

// AuthenMethod field values
const (
	AuthenMethodNotSet     = 0x00
	AuthenMethodNone       = 0x01
	AuthenMethodKRB5       = 0x02
	AuthenMethodLine       = 0x03
	AuthenMethodEnable     = 0x04
	AuthenMethodLocal      = 0x05
	AuthenMethodTACACSPlus = 0x06
	AuthenMethodGuest      = 0x08
	AuthenMethodRADIUS     = 0x10
	AuthenMethodKRB4       = 0x11
	AuthenMethodRCMD       = 0x20
)

// AuthenService field values
const (
	AuthenServiceNone    = 0x0
	AuthenServiceLogin   = 0x1
	AuthenServiceEnable  = 0x2
	AuthenServicePPP     = 0x3
	AuthenServiceARAP    = 0x4
	AuthenServicePT      = 0x5
	AuthenServiceRCMD    = 0x6
	AuthenServiceX25     = 0x7
	AuthenServiceNASI    = 0x8
	AuthenServiceFWProxy = 0x9
)

// AuthenType field values
const (
	AuthenTypeASCII  = 0x1
	AuthenTypePAP    = 0x2
	AuthenTypeCHAP   = 0x3
	AuthenTypeARAP   = 0x4
	AuthenTypeMSCHAP = 0x5
)

// AuthenStart Action field values
const (
	AuthenActionLogin      = 0x1
	AuthenActionChangePass = 0x2
	AuthenActionSendPass   = 0x3
	AuthenActionSendAuth   = 0x4
)

// AuthenReply Status field values
const (
	AuthenStatusPass    = 0x1
	AuthenStatusFail    = 0x2
	AuthenStatusGetData = 0x3
	AuthenStatusGetUser = 0x4
	AuthenStatusGetPass = 0x5
	AuthenStatusRestart = 0x6
	AuthenStatusError   = 0x7
	AuthenStatusFollow  = 0x21
)

// AuthorResponse Status field values
const (
	AuthorStatusPassAdd  = 0x1
	AuthorStatusPassRepl = 0x2
	AuthorStatusFail     = 0x3
	AuthorStatusError    = 0x4
	AuthorStatusFollow   = 0x5
)

// AcctRequest Flags field values
const (
	AcctFlagMore     = 0x1
	AcctFlagStart    = 0x2
	AcctFlagStop     = 0x4
	AcctFlagWatchdog = 0x8
)

// AcctReply Status field values
const (
	AcctStatusSuccess = 0x1
	AcctStatusError   = 0x2
	AcctStatusFollow  = 0x21
)

var errBadPacket = errors.New("bad secret or packet")

type readBuf []byte

func (b *readBuf) byte() byte {
	c := (*b)[0]
	*b = (*b)[1:]
	return c
}

func (b *readBuf) uint16() int {
	n := int((*b)[0])<<8 | int((*b)[1])
	*b = (*b)[2:]
	return n
}

func (b *readBuf) bytes(n int) []byte {
	buf := append([]byte(nil), (*b)[:n]...)
	*b = (*b)[n:]
	return buf
}

func (b *readBuf) slice(n int) []byte {
	buf := (*b)[:n]
	*b = (*b)[n:]
	return buf
}

func (b *readBuf) string(n int) string {
	s := (*b)[:n]
	*b = (*b)[n:]
	return string(s)
}

func appendUint16(b []byte, i, j int) []byte {
	return append(b, byte(i>>8), byte(i), byte(j>>8), byte(j))
}

// AuthenStart is a TACACS+ authentication start packet.
type AuthenStart struct {
	Action        uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	User          string
	Port          string
	RemAddr       string
	Data          []byte
}

// version returns the expected TACACS+ protocol version for the AuthenStart packet
func (a *AuthenStart) version() uint8 {
	switch a.Action {
	case AuthenActionLogin:
		switch a.AuthenType {
		case AuthenTypePAP, AuthenTypeCHAP, AuthenTypeARAP, AuthenTypeMSCHAP:
			return verDefaultMinorOne
		}
	case AuthenActionSendAuth:
		switch a.AuthenType {
		case AuthenTypePAP, AuthenTypeCHAP, AuthenTypeMSCHAP:
			return verDefaultMinorOne
		}
	}
	return verDefault
}

func (a *AuthenStart) marshal() ([]byte, error) {
	size := 8
	if len(a.User) > math.MaxUint8 {
		return nil, errors.New("User field too large")
	}
	size += len(a.User)
	if len(a.Port) > math.MaxUint8 {
		return nil, errors.New("Port field too large")
	}
	size += len(a.Port)
	if len(a.RemAddr) > math.MaxUint8 {
		return nil, errors.New("RemAddr field too large")
	}
	size += len(a.RemAddr)
	if len(a.Data) > math.MaxUint8 {
		return nil, errors.New("Data field too large")
	}
	size += len(a.Data)
	b := make([]byte, hdrLen, size+hdrLen)

	b = append(b, a.Action, a.PrivLvl, a.AuthenType, a.AuthenService)
	b = append(b, uint8(len(a.User)), uint8(len(a.Port)), uint8(len(a.RemAddr)), uint8(len(a.Data)))
	b = append(b, a.User...)
	b = append(b, a.Port...)
	b = append(b, a.RemAddr...)
	b = append(b, a.Data...)

	return b, nil
}

func (a *AuthenStart) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 8 {
		return errBadPacket
	}
	a.Action = b.byte()
	a.PrivLvl = b.byte()
	a.AuthenType = b.byte()
	a.AuthenService = b.byte()
	ul := int(b.byte())
	pl := int(b.byte())
	rl := int(b.byte())
	dl := int(b.byte())
	if len(b) < ul+pl+rl+dl {
		return errBadPacket
	}
	a.User = b.string(ul)
	a.Port = b.string(pl)
	a.RemAddr = b.string(rl)
	a.Data = b.bytes(dl)

	return nil
}

// AuthenReply is a TACACS+ authentication reply packet.
type AuthenReply struct {
	Status    uint8
	NoEcho    bool
	ServerMsg string
	Data      []byte
}

// last returns whether the AuthenReply packet is the last packet in the session.
func (a *AuthenReply) last() bool {
	return a.Status < AuthenStatusGetData || a.Status > AuthenStatusGetPass
}

func (a *AuthenReply) flags() uint8 {
	if a.NoEcho {
		return authenReplyFlagNoEcho
	}
	return 0
}

func (a *AuthenReply) marshal() ([]byte, error) {
	size := 6
	if len(a.ServerMsg) > math.MaxUint16 {
		return nil, errors.New("ServerMsg field too large")
	}
	size += len(a.ServerMsg)
	if len(a.Data) > math.MaxUint16 {
		return nil, errors.New("Data field too large")
	}
	size += len(a.Data)

	b := make([]byte, hdrLen, size+hdrLen)
	b = append(b, a.Status, a.flags())
	b = appendUint16(b, len(a.ServerMsg), len(a.Data))
	b = append(b, a.ServerMsg...)
	b = append(b, a.Data...)

	return b, nil
}

func (a *AuthenReply) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 6 {
		return errBadPacket
	}
	a.Status = b.byte()
	a.NoEcho = b.byte()&authenReplyFlagNoEcho > 0
	sl := b.uint16()
	dl := b.uint16()

	if len(b) < sl+dl {
		return errBadPacket
	}
	a.ServerMsg = b.string(sl)
	a.Data = b.bytes(dl)

	return nil
}

// authenContinue is a TACACS+ authentication continue packet.
type authenContinue struct {
	Abort   bool
	UserMsg string
	Data    []byte
}

func (a *authenContinue) flags() uint8 {
	if a.Abort {
		return authenContinueFlagAbort
	}
	return 0
}

func (a *authenContinue) marshal() ([]byte, error) {
	size := 5
	if len(a.UserMsg) > math.MaxUint16 {
		return nil, errors.New("UserMsg field too large")
	}
	size += len(a.UserMsg)
	if len(a.Data) > math.MaxUint16 {
		return nil, errors.New("Data field too large")
	}
	size += len(a.Data)

	b := make([]byte, hdrLen, size+hdrLen)
	b = appendUint16(b, len(a.UserMsg), len(a.Data))
	b = append(b, a.flags())
	b = append(b, a.UserMsg...)
	b = append(b, a.Data...)

	return b, nil
}

func (a *authenContinue) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 5 {
		return errBadPacket
	}
	ul := b.uint16()
	dl := b.uint16()
	a.Abort = b.byte()&authenContinueFlagAbort > 0
	if len(b) < ul+dl {
		return errBadPacket
	}
	a.UserMsg = b.string(ul)
	a.Data = b.bytes(dl)

	return nil
}

// AuthorRequest is a TACACS+ authorization request packet.
type AuthorRequest struct {
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	User          string
	Port          string
	RemAddr       string
	Arg           []string
}

func (a *AuthorRequest) marshal() ([]byte, error) {
	size := 8
	if len(a.User) > math.MaxUint8 {
		return nil, errors.New("User field too large")
	}
	size += len(a.User)
	if len(a.Port) > math.MaxUint8 {
		return nil, errors.New("Port field too large")
	}
	size += len(a.Port)
	if len(a.RemAddr) > math.MaxUint8 {
		return nil, errors.New("RemAddr field too large")
	}
	size += len(a.RemAddr)
	if len(a.Arg) > math.MaxUint8 {
		return nil, errors.New("Too many Arg's")
	}
	size += len(a.Arg)

	for _, s := range a.Arg {
		if len(s) > math.MaxUint8 {
			return nil, errors.New("Arg Too Long")
		}
		size += len(s)
	}

	b := make([]byte, hdrLen, size+hdrLen)
	b = append(b, a.AuthenMethod, a.PrivLvl, a.AuthenType, a.AuthenService)
	b = append(b, uint8(len(a.User)), uint8(len(a.Port)), uint8(len(a.RemAddr)), uint8(len(a.Arg)))
	for _, s := range a.Arg {
		b = append(b, uint8(len(s)))
	}
	b = append(b, a.User...)
	b = append(b, a.Port...)
	b = append(b, a.RemAddr...)
	for _, s := range a.Arg {
		b = append(b, s...)
	}

	return b, nil
}

func (a *AuthorRequest) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 8 {
		return errBadPacket
	}
	a.AuthenMethod = b.byte()
	a.PrivLvl = b.byte()
	a.AuthenType = b.byte()
	a.AuthenService = b.byte()
	ul := int(b.byte())
	pl := int(b.byte())
	rl := int(b.byte())
	ac := int(b.byte())
	if len(b) < ul+pl+rl+ac {
		return errBadPacket
	}
	al := b.slice(ac)
	a.User = b.string(ul)
	a.Port = b.string(pl)
	a.RemAddr = b.string(rl)
	a.Arg = make([]string, ac)
	for i, n := range al {
		if len(b) < int(n) {
			return errBadPacket
		}
		a.Arg[i] = b.string(int(n))
	}
	return nil
}

// AuthorResponse is a TACACS+ authorization response packet.
type AuthorResponse struct {
	Status    uint8
	Arg       []string
	ServerMsg string
	Data      string
}

func (a *AuthorResponse) marshal() ([]byte, error) {
	size := 6
	if len(a.Arg) > math.MaxUint8 {
		return nil, errors.New("Too many Arg's")
	}
	size += len(a.Arg)
	if len(a.ServerMsg) > math.MaxUint16 {
		return nil, errors.New("ServerMsg field too large")
	}
	size += len(a.ServerMsg)
	if len(a.Data) > math.MaxUint16 {
		return nil, errors.New("Data field too large")
	}
	size += len(a.Data)

	for _, s := range a.Arg {
		if len(s) > math.MaxUint8 {
			return nil, errors.New("Arg Too Long")
		}
		size += len(s)
	}

	b := make([]byte, hdrLen, size+hdrLen)
	b = append(b, a.Status, uint8(len(a.Arg)))
	b = appendUint16(b, len(a.ServerMsg), len(a.Data))
	for _, s := range a.Arg {
		b = append(b, uint8(len(s)))
	}
	b = append(b, a.ServerMsg...)
	b = append(b, a.Data...)
	for _, s := range a.Arg {
		b = append(b, s...)
	}

	return b, nil
}

func (a *AuthorResponse) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 6 {
		return errBadPacket
	}
	a.Status = b.byte()
	ac := int(b.byte())
	sl := b.uint16()
	dl := b.uint16()
	if len(b) < ac+sl+dl {
		return errBadPacket
	}
	al := b.slice(ac)
	a.ServerMsg = b.string(sl)
	a.Data = b.string(dl)
	a.Arg = make([]string, ac)
	for i, n := range al {
		if len(b) < int(n) {
			return errBadPacket
		}
		a.Arg[i] = b.string(int(n))
	}
	return nil
}

// AcctRequest is a TACACS+ accounting request packet.
type AcctRequest struct {
	Flags         uint8
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	User          string
	Port          string
	RemAddr       string
	Arg           []string
}

func (a *AcctRequest) marshal() ([]byte, error) {
	size := 9
	if len(a.User) > math.MaxUint8 {
		return nil, errors.New("User field too large")
	}
	size += len(a.User)
	if len(a.Port) > math.MaxUint8 {
		return nil, errors.New("Port field too large")
	}
	size += len(a.Port)
	if len(a.RemAddr) > math.MaxUint8 {
		return nil, errors.New("RemAddr field too large")
	}
	size += len(a.RemAddr)
	if len(a.Arg) > math.MaxUint8 {
		return nil, errors.New("Too many Arg's")
	}
	size += len(a.Arg)

	for _, s := range a.Arg {
		if len(s) > math.MaxUint8 {
			return nil, errors.New("Arg Too Long")
		}
		size += len(s)
	}

	b := make([]byte, hdrLen, size+hdrLen)
	b = append(b, a.Flags, a.AuthenMethod, a.PrivLvl, a.AuthenType, a.AuthenService)
	b = append(b, uint8(len(a.User)), uint8(len(a.Port)), uint8(len(a.RemAddr)), uint8(len(a.Arg)))
	for _, s := range a.Arg {
		b = append(b, uint8(len(s)))
	}
	b = append(b, a.User...)
	b = append(b, a.Port...)
	b = append(b, a.RemAddr...)
	for _, s := range a.Arg {
		b = append(b, s...)
	}

	return b, nil
}

func (a *AcctRequest) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 9 {
		return errBadPacket
	}
	a.Flags = b.byte()
	a.AuthenMethod = b.byte()
	a.PrivLvl = b.byte()
	a.AuthenType = b.byte()
	a.AuthenService = b.byte()
	ul := int(b.byte())
	pl := int(b.byte())
	rl := int(b.byte())
	ac := int(b.byte())
	if len(b) < ul+pl+rl+ac {
		return errBadPacket
	}
	al := b.slice(ac)
	a.User = b.string(ul)
	a.Port = b.string(pl)
	a.RemAddr = b.string(rl)
	a.Arg = make([]string, ac)
	for i, n := range al {
		if len(b) < int(n) {
			return errBadPacket
		}
		a.Arg[i] = b.string(int(n))
	}
	return nil
}

// AcctReply is a TACACS+ accounting reply packet.
type AcctReply struct {
	Status    uint8
	ServerMsg string
	Data      string
}

func (a *AcctReply) marshal() ([]byte, error) {
	size := 5
	if len(a.ServerMsg) > math.MaxUint16 {
		return nil, errors.New("ServerMsg field too large")
	}
	size += len(a.ServerMsg)
	if len(a.Data) > math.MaxUint16 {
		return nil, errors.New("Data field too large")
	}
	size += len(a.Data)

	b := make([]byte, hdrLen, size+hdrLen)
	b = appendUint16(b, len(a.ServerMsg), len(a.Data))
	b = append(b, a.Status)
	b = append(b, a.ServerMsg...)
	b = append(b, a.Data...)

	return b, nil
}

func (a *AcctReply) unmarshal(buf []byte) error {
	b := readBuf(buf)
	if len(b) < 5 {
		return errBadPacket
	}
	sl := b.uint16()
	dl := b.uint16()
	a.Status = b.byte()
	if len(b) < sl+dl {
		return errBadPacket
	}
	a.ServerMsg = b.string(sl)
	a.Data = b.string(dl)
	return nil
}

// nullPacket represents an empty packet.
type nullPacket struct{}

func (p *nullPacket) marshal() ([]byte, error) {
	return make([]byte, hdrLen), nil
}

func (p *nullPacket) unmarshal(buf []byte) error {
	return nil
}
