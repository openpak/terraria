package pia

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestRoundTripEncrypted(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32) // a NEX session key is 32 bytes; PIA uses the first 16
	msgs := []Message{
		{Flags: 1, SrcStation: 0, Destination: 0x5d949b50, SrcConstant: 1234, Protocol: ProtoStation, Port: 0, Payload: []byte{1, 7, 3, 0, 9}},
		{Protocol: ProtoUnreliable, Port: 1, Payload: []byte("terraria")},
	}
	raw, err := Encode(Header{Encrypted: true, Connection: 7, PacketID: 1, SrcTimer: 10}, msgs, key)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPIA(raw) || raw[4] != 2 || (len(raw)-HeaderLen-SigLen)%16 != 0 {
		t.Fatalf("raw %x", raw)
	}
	p, err := Decode(raw, key)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Encrypted || p.Connection != 7 || p.PacketID != 1 || len(p.Messages) != 2 {
		t.Fatalf("%+v", p)
	}
	if p.Messages[0].Destination != 0x5d949b50 || p.Messages[0].Protocol != ProtoStation || !bytes.Equal(p.Messages[0].Payload, []byte{1, 7, 3, 0, 9}) {
		t.Fatalf("m0 %+v", p.Messages[0])
	}
	if string(p.Messages[1].Payload) != "terraria" || ProtoName(p.Messages[1].Protocol) != "unreliable" {
		t.Fatalf("m1 %+v", p.Messages[1])
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	raw, _ := Encode(Header{Encrypted: true}, []Message{{Protocol: ProtoNAT, Payload: []byte{1}}}, key)
	raw[HeaderLen] ^= 1
	if _, err := Decode(raw, key); err != ErrSignature {
		t.Fatalf("err %v", err)
	}
	if _, err := Decode(raw, bytes.Repeat([]byte{2}, 16)); err != ErrSignature {
		t.Fatal("wrong key must fail the signature")
	}
}

func TestPlainUnsigned(t *testing.T) {
	raw, _ := Encode(Header{}, []Message{{Protocol: ProtoNAT, Payload: []byte{1, 2, 3}}}, nil)
	p, err := Decode(raw, nil)
	if err != nil || p.Encrypted || len(p.Messages) != 1 || p.Messages[0].Protocol != ProtoNAT {
		t.Fatalf("%v %+v", err, p)
	}
	if _, err := Decode([]byte("nope nope nope"), nil); err != ErrMagic {
		t.Fatal("magic")
	}
}

// A real station connection request from Terraria (Wii U) in Quay (2026-11-06, prds#145): plain, signed with HMAC-MD5 keyed by the
// full 32-byte session key. The key is not in the repo; only the layout is checked here.
func TestRealConnectionRequestLayout(t *testing.T) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(must(os.ReadFile("testdata/quay-connreq.hex")))))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(raw[:len(raw)-SigLen], nil) // strip the signature, decode unsigned
	if err != nil {
		t.Fatal(err)
	}
	if p.Encrypted || p.Connection != 1 || len(p.Messages) != 1 {
		t.Fatalf("%+v", p)
	}
	m := p.Messages[0]
	if m.Protocol != ProtoStation || m.SrcStation != 0xfd || len(m.Payload) != 62 || m.Payload[0] != 1 || m.Payload[2] != 3 {
		t.Fatalf("message %+v", m)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
