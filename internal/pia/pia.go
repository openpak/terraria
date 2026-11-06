// Package pia is the packet layer of Nintendo's PIA peer-to-peer library as Terraria (Wii U) uses it: PIA 3.x, the message
// format "up to 5.4" and the packet header "up to 5.6" documented on github.com/kinnay/NintendoClients/wiki (PIA Protocol).
//
// Packet: a 12-byte clear header, then the messages, AES-128-ECB encrypted when the header says so (padded with 0xFF to 16),
// then HMAC-MD5 over header and (encrypted) body. Key: the first 16 bytes of the NEX MatchmakeSession session key, which the
// OpenPak NEX server generates. All integers are big-endian.
package pia

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// Magic starts every PIA packet.
var Magic = [4]byte{0x32, 0xAB, 0x98, 0x64}

const (
	HeaderLen    = 12
	MsgHeaderLen = 20
	SigLen       = md5.Size

	flagPlain     = 1
	flagEncrypted = 2
)

// Protocol type ids of PIA 3.3-3.10 (wiki: Pia Protocols).
const (
	ProtoRelay       = 0x0080
	ProtoKeepAlive   = 0x00C0
	ProtoStation     = 0x0100
	ProtoSession     = 0x0200
	ProtoSessionClk  = 0x0210
	ProtoNAT         = 0x0400
	ProtoGateway     = 0x0410
	ProtoRTT         = 0x0600
	ProtoSyncOld     = 0x1800
	ProtoSync        = 0x1810
	ProtoUnreliable  = 0x2000
	ProtoRoundrobin  = 0x2100
	ProtoClone       = 0x2400
	ProtoVoice       = 0x2800
	ProtoReliable    = 0x3000
	ProtoReliableBC  = 0x7000
	ProtoMatch       = 0x7200
	ProtoFeedback    = 0x8000
	ProtoRelayServce = 0x8200
)

// ProtoName names a protocol type for logs.
func ProtoName(t uint16) string {
	if n, ok := map[uint16]string{ProtoRelay: "relay", ProtoKeepAlive: "keepalive", ProtoStation: "station", ProtoSession: "session",
		ProtoSessionClk: "session-clock", ProtoNAT: "nat", ProtoGateway: "gateway", ProtoRTT: "rtt", ProtoSyncOld: "sync-old",
		ProtoSync: "sync", ProtoUnreliable: "unreliable", ProtoRoundrobin: "roundrobin-unreliable", ProtoClone: "clone",
		ProtoVoice: "voice", ProtoReliable: "reliable", ProtoReliableBC: "reliable-broadcast", ProtoMatch: "match",
		ProtoFeedback: "feedback", ProtoRelayServce: "relay-service"}[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", t)
}

// Header is the clear 12-byte packet header.
type Header struct {
	Encrypted  bool
	Connection uint8
	PacketID   uint16
	SrcTimer   uint16
	DstTimer   uint16
}

// Message is one message of a packet (format up to 5.4).
type Message struct {
	Flags       uint8
	SrcStation  uint8
	Destination uint32
	SrcConstant uint32
	Protocol    uint16
	Port        uint16
	Payload     []byte
}

// Packet is a decoded packet.
type Packet struct {
	Header
	Messages []Message
}

var (
	ErrMagic     = errors.New("pia: bad magic")
	ErrShort     = errors.New("pia: short packet")
	ErrSignature = errors.New("pia: bad signature")
)

// Key is the 16-byte packet key from a NEX session key (longer keys are cut, per the wiki).
func Key(sessionKey []byte) []byte {
	if len(sessionKey) > 16 {
		return sessionKey[:16]
	}
	return sessionKey
}

// IsPIA reports whether b starts like a PIA packet.
func IsPIA(b []byte) bool { return len(b) >= HeaderLen && bytes.Equal(b[:4], Magic[:]) }

// Decode checks the signature, decrypts and splits a packet. key may be nil for plain packets.
func Decode(b, key []byte) (*Packet, error) {
	if len(b) < HeaderLen {
		return nil, ErrShort
	}
	if !bytes.Equal(b[:4], Magic[:]) {
		return nil, ErrMagic
	}
	p := &Packet{Header: Header{Encrypted: b[4] == flagEncrypted, Connection: b[5],
		PacketID: binary.BigEndian.Uint16(b[6:]), SrcTimer: binary.BigEndian.Uint16(b[8:]), DstTimer: binary.BigEndian.Uint16(b[10:])}}
	body := b[HeaderLen:]
	if key != nil {
		if len(body) < SigLen {
			return nil, ErrShort
		}
		sig := body[len(body)-SigLen:]
		body = body[:len(body)-SigLen]
		if !hmac.Equal(sign(key, b[:HeaderLen], body), sig) {
			return p, ErrSignature
		}
	}
	if p.Encrypted {
		if key == nil {
			return p, errors.New("pia: encrypted packet and no key")
		}
		if len(body)%aes.BlockSize != 0 {
			return p, fmt.Errorf("pia: encrypted body of %d bytes", len(body))
		}
		c, err := aes.NewCipher(Key(key))
		if err != nil {
			return p, err
		}
		plain := make([]byte, len(body))
		for i := 0; i < len(body); i += aes.BlockSize {
			c.Decrypt(plain[i:], body[i:i+aes.BlockSize])
		}
		body = plain
	}
	msgs, err := splitMessages(body)
	p.Messages = msgs
	return p, err
}

func sign(key, header, body []byte) []byte {
	m := hmac.New(md5.New, Key(key))
	m.Write(header)
	m.Write(body)
	return m.Sum(nil)
}

func splitMessages(b []byte) ([]Message, error) {
	var out []Message
	for len(b) >= MsgHeaderLen {
		if b[0] == 0xFF && bytes.Count(b, []byte{0xFF}) == len(b) {
			break // encryption padding
		}
		m := Message{Flags: b[0], SrcStation: b[1], Destination: binary.BigEndian.Uint32(b[4:]),
			SrcConstant: binary.BigEndian.Uint32(b[8:]), Protocol: binary.BigEndian.Uint16(b[12:]), Port: binary.BigEndian.Uint16(b[14:])}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if MsgHeaderLen+n > len(b) {
			return out, fmt.Errorf("pia: message payload %d over %d bytes left", n, len(b)-MsgHeaderLen)
		}
		m.Payload = append([]byte(nil), b[MsgHeaderLen:MsgHeaderLen+n]...)
		out = append(out, m)
		adv := (MsgHeaderLen + n + 3) &^ 3
		if adv > len(b) {
			adv = len(b)
		}
		b = b[adv:]
	}
	return out, nil
}

// Encode builds a packet. With a key the packet is signed, and encrypted when h.Encrypted.
func Encode(h Header, msgs []Message, key []byte) ([]byte, error) {
	var body []byte
	for _, m := range msgs {
		var mh [MsgHeaderLen]byte
		mh[0], mh[1] = m.Flags, m.SrcStation
		binary.BigEndian.PutUint16(mh[2:], uint16(len(m.Payload)))
		binary.BigEndian.PutUint32(mh[4:], m.Destination)
		binary.BigEndian.PutUint32(mh[8:], m.SrcConstant)
		binary.BigEndian.PutUint16(mh[12:], m.Protocol)
		binary.BigEndian.PutUint16(mh[14:], m.Port)
		body = append(body, mh[:]...)
		body = append(body, m.Payload...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
	}
	hdr := make([]byte, HeaderLen)
	copy(hdr, Magic[:])
	hdr[4] = flagPlain
	if h.Encrypted {
		hdr[4] = flagEncrypted
	}
	hdr[5] = h.Connection
	binary.BigEndian.PutUint16(hdr[6:], h.PacketID)
	binary.BigEndian.PutUint16(hdr[8:], h.SrcTimer)
	binary.BigEndian.PutUint16(hdr[10:], h.DstTimer)
	if h.Encrypted {
		if key == nil {
			return nil, errors.New("pia: encrypt without a key")
		}
		for len(body)%aes.BlockSize != 0 {
			body = append(body, 0xFF)
		}
		c, err := aes.NewCipher(Key(key))
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(body); i += aes.BlockSize {
			c.Encrypt(body[i:], body[i:i+aes.BlockSize])
		}
	}
	out := append(hdr, body...)
	if key != nil {
		out = append(out, sign(key, hdr, body)...)
	}
	return out, nil
}
