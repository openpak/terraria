package rtsig

import (
	"bytes"
	"testing"
)

func TestFrameSignal(t *testing.T) {
	p := ProbePacket(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), 1, 2)
	w := FrameSignal(p)
	if !bytes.Equal(w[:6], []byte{0xff, 0x83, 0xff, 0xfe, 0xff, 0xfe}) || !bytes.Equal(w[6:], p) {
		t.Fatalf("header % x", w[:6])
	}
	k, s, d, pl, err := Unframe(w)
	if err != nil || k != KindPlain || s != VPortSignal || d != VPortSignal || !bytes.Equal(pl, p) {
		t.Fatal("round trip", k, s, d, err)
	}
}

func TestFrameCompact(t *testing.T) {
	w := Frame(KindPlain, 1, 1, []byte{9})
	if !bytes.Equal(w, []byte{0xff, 0xc3, 1, 1, 9}) {
		t.Fatalf("% x", w)
	}
	if _, s, d, pl, err := Unframe(w); err != nil || s != 1 || d != 1 || !bytes.Equal(pl, []byte{9}) {
		t.Fatal("compact round trip")
	}
}

func TestUnframeRejects(t *testing.T) {
	for _, b := range [][]byte{nil, {0xff}, {0x01, 0x83, 0, 0, 0, 0}, {0xff, 0x03, 0, 0, 0, 0}, {0xff, 0x83, 0xff}, {0xff, 0xc3, 1}, {0xff, 0x82, 0, 0, 0, 0}, {0xff, 0x8b, 0, 0, 0, 0}} {
		if _, _, _, _, err := Unframe(b); err == nil {
			t.Fatalf("accepted % x", b)
		}
	}
	if k, _, _, pl, err := Unframe([]byte{0xff, 0x87}); err != nil || k != 7 || pl != nil {
		t.Fatal("unreachable reply")
	}
}
