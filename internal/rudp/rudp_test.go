package rudp

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// The decompile's recipe for the first packet on the wire (ISN 0x1000, connId 0x01020304).
func TestFirstPacketBytes(t *testing.T) {
	got := frame(synPacket(0x1000, 0x01020304))
	want, _ := hex.DecodeString("401280ff10000000010001000102030404b0")
	if !bytes.Equal(got, want) {
		t.Fatalf("first packet %x, want %x", got, want)
	}
}

func udpPair(t *testing.T) (*net.UDPConn, *net.UDPConn, *net.UDPAddr, *net.UDPAddr) {
	t.Helper()
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return a, b, b.LocalAddr().(*net.UDPAddr), a.LocalAddr().(*net.UDPAddr)
}

// Two of our peers complete the simultaneous open and exchange a payload each way.
func TestSimultaneousOpenAndData(t *testing.T) {
	sockA, sockB, addrB, addrA := udpPair(t)
	defer sockA.Close()
	defer sockB.Close()
	a := New(sockA, addrB, 0x1000, 0x01020304)
	b := New(sockB, addrA, 0x2000, 0x05060708)
	aPayload := make(chan []byte, 1)
	bPayload := make(chan []byte, 1)
	a.OnPayload = func(p []byte) { aPayload <- p }
	b.OnPayload = func(p []byte) { bPayload <- p }
	go a.Serve()
	go b.Serve()
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !(a.Established() && b.Established()) {
		if time.Now().After(deadline) {
			t.Fatalf("handshake incomplete: a=%v b=%v", a.Established(), b.Established())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := a.Send([]byte{0, 0}); err != nil { // host -> joiner shape: [00][slot]
		t.Fatal(err)
	}
	if got := <-bPayload; !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("b payload %x", got)
	}
	if err := b.Send([]byte{1, 1, 1}); err != nil { // joiner Hello [01][01][slot]
		t.Fatal(err)
	}
	if got := <-aPayload; !bytes.Equal(got, []byte{1, 1, 1}) {
		t.Fatalf("a payload %x", got)
	}
	// A SYN+ACK with the wrong ack is refused.
	c := New(sockA, addrB, 0x3000, 1)
	bad := synAckPacket(0x4000, 0x9999, 2)
	if err := c.handlePacket(bad); err == nil {
		t.Fatal("synack with wrong ack accepted")
	}
}
