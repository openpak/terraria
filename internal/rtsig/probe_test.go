package rtsig

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

// Live run 2026-11-10 (card #145): joiner SwitchTest sid 49549 (0xc18d), host PS3Test sid 37278 (0x919e).
const (
	liveSelf = "SwitchTest@us.us.np.playstation.net/ps3"
	liveHost = "PS3Test@us.us.np.playstation.net/ps3"
)

func TestNpIDFromJID(t *testing.T) {
	b, err := NpIDFromJID(liveSelf)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("5377697463685465737400000000000075737573707333000100000000000000")
	if !bytes.Equal(b, want) {
		t.Fatalf("npid %x", b)
	}
	if _, err := NpIDFromJID("x@np.playstation.net"); err == nil {
		t.Fatal("bad domain accepted")
	}
}

func TestProbeLayout(t *testing.T) {
	own, _ := NpIDFromJID(liveSelf)
	peer, _ := NpIDFromJID(liveHost)
	pkt := ProbePacket(own, peer, 0xc18d, 0x919e, 0x0102030405060708)
	want, _ := hex.DecodeString("01000000" +
		"5377697463685465737400000000000075737573707333000100000000000000" +
		"5053335465737400000000000000000075737573707333000100000000000000" +
		"c18d919e" + "0102030405060708" + "0000000000000000")
	if !bytes.Equal(pkt, want) {
		t.Fatalf("probe\n got %x\nwant %x", pkt, want)
	}
	// The host's probe to us mirrors it; our own probe hairpinned back must not pass as the host's.
	hostPkt := ProbePacket(peer, own, 0x919e, 0xc18d, 1)
	if !ProbeFrom(hostPkt, own, peer) || ProbeFrom(pkt, own, peer) {
		t.Fatal("ProbeFrom direction")
	}
	// The 2026-11-10 "host probes" were our old skey-format probes reflected by the NAT: never the host's.
	live, _ := hex.DecodeString("0100000004778f954218595659b1b3e02ae27694000000000000000000000000000000008b7caf368e2f5961d81710d4008cd4b100000000000000000000000000000000c18d919e00000000000000000000000000000000")
	if ProbeFrom(live, own, peer) {
		t.Fatal("captured reflection accepted as host probe")
	}
}

func TestProbeResponse(t *testing.T) {
	own, _ := NpIDFromJID(liveSelf)
	peer, _ := NpIDFromJID(liveHost)
	req := ProbePacket(peer, own, 0x919e, 0xc18d, 0x1122334455667788)
	src := &net.UDPAddr{IP: net.IPv4(10, 87, 0, 11), Port: 3658}
	resp := ProbeResponsePacket(req, src, own, peer, 0xc18d, 0x919e)
	want, _ := hex.DecodeString("02000000" +
		"5377697463685465737400000000000075737573707333000100000000000000" +
		"5053335465737400000000000000000075737573707333000100000000000000" +
		"c18d919e" + "1122334455667788" +
		"cbda9195" + // 0a57000b ^ c18d919e
		"cfc7" + // 0e4a ^ c18d
		"0000")
	if !bytes.Equal(resp, want) {
		t.Fatalf("response\n got %x\nwant %x", resp, want)
	}
	if m := ProbeMapped(resp); m == nil || m.String() != "10.87.0.11:3658" {
		t.Fatalf("mapped %v", m)
	}
	if ProbeResponsePacket(resp, src, own, peer, 1, 2) != nil {
		t.Fatal("answered a type-2")
	}
}
