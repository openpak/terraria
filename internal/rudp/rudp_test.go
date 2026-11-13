package rudp

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

// The two datagrams a real PS3 (Terraria v01.12) sent on run live10, 2026-11-13: its SYN (four times, 1/2/4/8 s apart) and, 30 s
// after the first, its reset when nobody answered. Decoded in research/ps3/matching2-protocol.md §43.
const (
	realSyn   = "ffc301018014000180303d4c020101000100f8ba92b10582"
	realReset = "ffc30101800e0001c00000000003f8ba92b1"
)

func hx(s string) []byte { b, _ := hex.DecodeString(strings.ReplaceAll(s, " ", "")); return b }

type capture struct{ out [][]byte }

func (c *capture) put(d []byte) { c.out = append(c.out, append([]byte(nil), d...)) }
func (c *capture) take(t *testing.T, want ...string) {
	t.Helper()
	if len(c.out) != len(want) {
		t.Fatalf("sent %d datagrams %x, want %d", len(c.out), c.out, len(want))
	}
	for i, w := range want {
		if !bytes.Equal(c.out[i], hx(w)) {
			t.Errorf("datagram %d = %x, want %s", i, c.out[i], strings.ReplaceAll(w, " ", ""))
		}
	}
	c.out = nil
}

func newTestConn() (*Conn, *capture) {
	cp := &capture{}
	c := New(nil, nil, 0x1000, 0x01020304)
	c.Out = cp.put
	return c, cp
}

// Our own SYN has the console's layout: UDPP2P ff c3 01 01, class-2 frame to RUDP port 1, window 0x30, cap 0x0201, both versions
// 0x0100, connection id, MSS 0x0582.
func TestOurSynIsTheConsolesLayout(t *testing.T) {
	c, cp := newTestConn()
	c.StartAt(time.Unix(0, 0))
	cp.take(t, "ffc301018014 0001 8030 1000 0201 0100 0100 01020304 0582")
}

// Replaying the console's SYN: our reply is the SYN+ACK librudp's SYN-SENT state sends (ack = its ISN + 1 = 0x3d4d, our own SYN
// block), byte for byte. The console's capability word 0x0201 is mirrored.
func TestReplayRealSynGetsSynAck(t *testing.T) {
	c, cp := newTestConn()
	var lines []string
	c.Trace = func(dir, desc string, _ []byte) { lines = append(lines, dir+" "+desc) }
	c.StartAt(time.Unix(0, 0))
	cp.out = nil
	if err := c.HandleDatagram(hx(realSyn)); err != nil {
		t.Fatal(err)
	}
	cp.take(t, "ffc301018016 0001 a030 1000 3d4d 0201 0100 0100 01020304 0582")
	if c.PeerMSS() != 0x582 {
		t.Errorf("peer mss %d", c.PeerMSS())
	}
	if c.Established() {
		t.Error("established on a SYN alone")
	}
	log := strings.Join(lines, "\n")
	for _, w := range []string{"SYN flags=0x00 win=0x30 seq=0x3d4c cap=0x0201 verA=0x0100 verB=0x0100 connid=0xf8ba92b1 mss=1410", "udpp2p kind=3 vport 0x1->0x1"} {
		if !strings.Contains(log, w) {
			t.Errorf("trace lacks %q:\n%s", w, log)
		}
	}
	// A retransmitted SYN (the console's back-off) is answered again, not dropped.
	c.HandleDatagram(hx(realSyn))
	cp.take(t, "ffc301018016 0001 a030 1000 3d4d 0201 0100 0100 01020304 0582")
	// The console completes with a data packet carrying the ack flag (librudp FUN_0001c580, state 3): synthetic, from the decode.
	est := false
	c.OnEstablished = func() { est = true }
	c.HandleDatagram(hx("ffc30101800a 0001 2030 3d4d 1001"))
	if !est || !c.Established() {
		t.Fatal("not established by the console's ack")
	}
	cp.take(t)
}

// The console's reset (reason 3 = connect timeout, its own connection id) is recorded, never answered and never an error.
func TestReplayRealResetIsRecorded(t *testing.T) {
	c, cp := newTestConn()
	c.StartAt(time.Unix(0, 0))
	cp.out = nil
	var gotReason byte
	var gotID uint32
	c.OnReset = func(r byte, id uint32) { gotReason, gotID = r, id }
	if err := c.HandleDatagram(hx(realReset)); err != nil {
		t.Fatal(err)
	}
	cp.take(t)
	if gotReason != 3 || gotID != 0xf8ba92b1 {
		t.Errorf("reset reason %d id %#x", gotReason, gotID)
	}
	if got := Describe(hx("c0 00 0000 0003 f8ba92b1")); got != "RESET flags=0x00 win=0x00 seq=0x0000 reason=3 connid=0xf8ba92b1" {
		t.Errorf("describe %q", got)
	}
}

// The other way: the console already holds our SYN and answers with a SYN+ACK (ack = our ISN+1). We ack with an empty data packet
// (seq = our ISN+1, ack = its ISN+1), then data both ways with an ack per received segment.
func TestSynAckEstablishesAndData(t *testing.T) {
	c, cp := newTestConn()
	c.StartAt(time.Unix(0, 0))
	cp.out = nil
	var rx [][]byte
	c.OnPayload = func(b []byte) { rx = append(rx, b) }
	c.HandleDatagram(hx("ffc301018016 0001 a030 3d4c 1001 0201 0100 0100 f8ba92b1 0582"))
	if !c.Established() {
		t.Fatal("SYN+ACK did not establish")
	}
	cp.take(t, "ffc30101800a 0001 2030 1001 3d4d")
	if err := c.Send([]byte{1, 1, 1}); err != nil {
		t.Fatal(err)
	}
	cp.take(t, "ffc30101800d 0001 2030 1001 3d4d 010101")
	c.HandleDatagram(hx("ffc30101800c 0001 2030 3d4d 1002 aabb"))
	if len(rx) != 1 || !bytes.Equal(rx[0], []byte{0xaa, 0xbb}) {
		t.Fatalf("payload %x", rx)
	}
	cp.take(t, "ffc30101800a 0001 2030 1002 3d4e")
	// the same segment again is not delivered twice but is acked again
	c.HandleDatagram(hx("ffc30101800c 0001 2030 3d4d 1002 aabb"))
	if len(rx) != 1 {
		t.Fatal("duplicate delivered")
	}
	cp.take(t, "ffc30101800a 0001 2030 1002 3d4e")
	// its ack of our segment drops it from the retransmit queue
	c.HandleDatagram(hx("ffc30101800a 0001 2030 3d4e 1002"))
	c.Tick(time.Now().Add(2 * time.Second))
	if len(cp.out) != 0 {
		t.Errorf("acked segment retransmitted: %x", cp.out)
	}
}

// Things the console must never be able to make us abort on.
func TestBadInputIsTracedNotFatal(t *testing.T) {
	c, cp := newTestConn()
	c.StartAt(time.Unix(0, 0))
	cp.out = nil
	for name, d := range map[string]string{
		"bare frame without UDPP2P":  "4014 80ff10000000",
		"kernel unreachable":         "ff87",
		"wrong rudp port":            "ffc301018014 0002 8030 3d4c 0201 0100 0100 f8ba92b1 0582",
		"class 1 short":              "ffc30101 4003 00",
		"SYN+ACK with the wrong ack": "ffc301018016 0001 a030 3d4c 2222 0201 0100 0100 f8ba92b1 0582",
		"verA below 0x0100":          "ffc301018014 0001 8030 3d4c 0201 00ff 0100 f8ba92b1 0582",
		"short SYN block":            "ffc30101800c 0001 8030 3d4c 0201 0100",
		"frame longer than the data": "ffc30101 87ff 0001 8030",
	} {
		c.HandleDatagram(hx(d)) // must not panic
		if c.Established() {
			t.Errorf("%s: established", name)
		}
		if len(cp.out) != 0 {
			t.Errorf("%s: answered %x", name, cp.out)
			cp.out = nil
		}
	}
}

// librudp's retransmit timer: 1 s, then doubling to a 16 s cap.
func TestSynRetransmitSchedule(t *testing.T) {
	c, cp := newTestConn()
	t0 := time.Unix(100, 0)
	c.StartAt(t0)
	cp.out = nil
	now := t0
	for _, step := range []time.Duration{1, 2, 4, 8, 16, 16} {
		c.Tick(now.Add(step*time.Second - time.Millisecond))
		if len(cp.out) != 0 {
			t.Fatalf("early retransmit before %v", step)
		}
		now = now.Add(step * time.Second)
		c.Tick(now)
		if len(cp.out) != 1 {
			t.Fatalf("no retransmit at +%v", step)
		}
		cp.out = nil
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

// Two of our peers complete the simultaneous open over loopback and exchange a payload each way.
func TestSimultaneousOpenAndData(t *testing.T) {
	sockA, sockB, addrB, addrA := udpPair(t)
	defer sockA.Close()
	defer sockB.Close()
	a := New(sockA, addrB, 0x1000, 0x01020304)
	b := New(sockB, addrA, 0x2000, 0x05060708)
	defer a.Close()
	defer b.Close()
	aPayload := make(chan []byte, 1)
	bPayload := make(chan []byte, 1)
	a.OnPayload = func(p []byte) { aPayload <- p }
	b.OnPayload = func(p []byte) { bPayload <- p }
	go a.Serve()
	go b.Serve()
	a.Start()
	b.Start()
	deadline := time.Now().Add(5 * time.Second)
	for !(a.Established() && b.Established()) {
		if time.Now().After(deadline) {
			t.Fatalf("handshake incomplete: a=%v b=%v", a.Established(), b.Established())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := a.Send([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	if got := <-bPayload; !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("b payload %x", got)
	}
	if err := b.Send([]byte{1, 1, 1}); err != nil {
		t.Fatal(err)
	}
	if got := <-aPayload; !bytes.Equal(got, []byte{1, 1, 1}) {
		t.Fatalf("a payload %x", got)
	}
}
