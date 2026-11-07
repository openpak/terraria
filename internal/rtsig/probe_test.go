package rtsig

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestProbePacketLayout(t *testing.T) {
	own := bytes.Repeat([]byte{0x11}, 16)
	peer := bytes.Repeat([]byte{0x22}, 16)
	pkt := ProbePacket(own, peer, 0x1234, 0x5678)
	if len(pkt) != probeLen || pkt[0] != 1 {
		t.Fatalf("len/type = %d/%d", len(pkt), pkt[0])
	}
	if !bytes.Equal(pkt[0x04:0x14], peer) || !bytes.Equal(pkt[0x24:0x34], own) {
		t.Fatal("skey fields wrong")
	}
	if binary.BigEndian.Uint16(pkt[0x44:]) != 0x1234 || binary.BigEndian.Uint16(pkt[0x46:]) != 0x5678 {
		t.Fatal("sid fields wrong")
	}
	binary.BigEndian.PutUint32(pkt[0x50:], 0xDEADBEEF)
	resp := ProbeResponsePacket(pkt, peer, own, 0x5678, 0x1234)
	if got := binary.BigEndian.Uint32(resp[0x50:]); got != 0xDEADBEEF^(0x5678<<16|0x1234) {
		t.Fatalf("response +0x50 = %#x", got)
	}
	if resp == nil || resp[0] != 2 {
		t.Fatal("no type-2 response")
	}
	if !bytes.Equal(resp[0x04:0x14], own) || !bytes.Equal(resp[0x24:0x34], peer) {
		t.Fatal("response skeys not swapped")
	}
	if binary.BigEndian.Uint16(resp[0x44:]) != 0x5678 || binary.BigEndian.Uint16(resp[0x46:]) != 0x1234 {
		t.Fatal("response sids not swapped")
	}
}
