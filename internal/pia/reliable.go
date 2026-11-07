package pia

import (
	"encoding/binary"
	"errors"
)

// Reliable protocol (0x3000) as Terraria (Wii U) uses it, from the game's PIA library (Wii U ELF 0x27df000 send, 0x27de234 receive):
// a 24-byte big-endian header (u16 flags, u16 size, 4 zero bytes, u32 sequence, u32 ack = next expected, u64 extra acks: bit i
// acks ack+1+i), then the payload. Flags: 1 data, 2 last fragment; an ack-only message has flags 0 and size 0. Both sequence
// counters start at 0xFFFFF82F. The game's reliable channel is port 1; its unreliable channel (0x2000) is port 0 with no header.
const (
	ReliablePort     = 1
	UnreliablePort   = 0
	ReliableHdrLen   = 24
	ReliableFirstSeq = 0xFFFFF82F
	RelData          = 1
	RelLast          = 2
	RelMaxPayload    = 0x578
)

// ReliableMsg is one reliable-protocol message.
type ReliableMsg struct {
	Flags   uint16
	Seq     uint32
	Ack     uint32
	Extra   uint64
	Payload []byte
}

func (r ReliableMsg) IsData() bool { return r.Flags&RelData != 0 }

func (r ReliableMsg) Marshal() []byte {
	b := make([]byte, ReliableHdrLen, ReliableHdrLen+len(r.Payload))
	binary.BigEndian.PutUint16(b[0:], r.Flags)
	binary.BigEndian.PutUint16(b[2:], uint16(len(r.Payload)))
	binary.BigEndian.PutUint32(b[8:], r.Seq)
	binary.BigEndian.PutUint32(b[12:], r.Ack)
	binary.BigEndian.PutUint64(b[16:], r.Extra)
	return append(b, r.Payload...)
}

var ErrReliable = errors.New("pia: bad reliable message")

func ParseReliable(p []byte) (ReliableMsg, error) {
	if len(p) < ReliableHdrLen {
		return ReliableMsg{}, ErrReliable
	}
	n := int(binary.BigEndian.Uint16(p[2:]))
	if len(p) != ReliableHdrLen+n || n > RelMaxPayload {
		return ReliableMsg{}, ErrReliable
	}
	return ReliableMsg{Flags: binary.BigEndian.Uint16(p), Seq: binary.BigEndian.Uint32(p[8:]), Ack: binary.BigEndian.Uint32(p[12:]),
		Extra: binary.BigEndian.Uint64(p[16:]), Payload: append([]byte(nil), p[ReliableHdrLen:]...)}, nil
}
