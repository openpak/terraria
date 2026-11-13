// Package rudp is the cellRudp wire protocol (Sony librudp) as a Terraria PS3 peer speaks it over the lv2 UDPP2P kernel socket.
//
// Layers, outermost first (every field seen on a real PS3, run live10 2026-11-13, and read from librudp.prx 4.93):
//
//	UDPP2P   ff c3 01 01                    kind 3 plain, source vport 1, destination vport 1 (internal/rtsig.Frame)
//	frame    u16 (2<<14 | len) u16 port     class 2 = muxmode 1, len counts these 4 bytes and the packet, port = RUDP port (1)
//	packet   type<<6|flags, window, seq u16, [ack u16], [ts u16], type block, [options], payload
//
// Types: 0 data, 1 ack/keepalive, 2 SYN or SYN+ACK, 3 reset. Flags: 0x20 ack present, 0x10 options, 0x04 timestamp (needs ack).
// The window byte is `(b&0x3f) << ((b>>5)&6)` segments; the PS3 sends 0x30 (48). No checksum anywhere.
// SYN block (12 bytes): capWord, verA, verB, connId u32, MSS u16. capWord = 0x800 stream mode | 0x200 | 0x100 | low nibble; the
// receiver aborts the connection silently (no packet) unless the peer's 0x800/0x200/0x100 bits equal its own flags, so a peer that
// cannot know them mirrors what the console sent (0x0201 on Terraria's PS3). verA must be >= 0x0100 and verB <= 0x0100.
// Reset block (6 bytes): reason u16 (low byte; 3 = connect timeout) and the sender's own connId; the packet has window 0 and seq 0.
// SYN consumes one sequence number. Data acks are cumulative: the ack field is the next sequence number expected.
//
// Handshake (librudp FUN_0001d318 and its per-state jump table): a SYN in SYN-SENT moves to SYN-RECEIVED and is answered with a
// SYN+ACK (ack = peer ISN+1); a SYN+ACK whose ack is our ISN+1 in SYN-SENT or SYN-RECEIVED means ESTABLISHED; a data packet with
// the ack flag completes SYN-RECEIVED. The retransmit timer starts at 1 s and doubles to 16 s; after 30 s without a handshake the
// library sends a reset with reason 3. Nothing here ever aborts on what a peer sends: everything is traced and the connection goes on.
package rudp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/openpak/terraria/internal/rtsig"
)

const (
	flagAck  = 0x20
	flagOpts = 0x10
	flagTS   = 0x04

	typeData  = 0
	typeAck   = 1
	typeSyn   = 2
	typeReset = 3

	// WindowByte is the console's own window byte (48 segments), seen on hardware.
	WindowByte = 0x30
	// MSS is librudp's default (0x582 = 1410): no option is ever set, the console's SYN carries it. The usable payload is MSS-0x40.
	MSS = 0x582
	// DefaultCap is the capability word of the Terraria PS3's SYN. It is replaced by the peer's word once we have seen one.
	DefaultCap = 0x0201
	// VerWord is both version words of every SYN seen.
	VerWord = 0x0100

	rtoMax   = 16 * time.Second // retransmit timer cap, doubling from 1 s
	keepIdle = 5 * time.Second  // ponytail: the real idle timeout is unread (60000 ms in the option defaults, probably); 5 s is far under it
)

const (
	stSynSent = 2 // librudp's own numbering
	stSynRcvd = 3
	stEstab   = 4
	stClosed  = 1
)

// Conn is one RUDP peer connection over an existing UDP socket.
type Conn struct {
	UDP  *net.UDPConn
	Peer *net.UDPAddr

	Port  uint16 // RUDP port in the class-2 frame header (pad index + 1), 1 for the first player
	VPort uint16 // UDPP2P vport, both directions, 1 for the game socket

	// Out, if set, receives every complete UDP datagram instead of the socket (tests).
	Out func([]byte)
	// Trace sees every datagram problem and every packet in both directions with a one-line description.
	Trace func(dir, desc string, pkt []byte)

	OnPayload     func([]byte)
	OnEstablished func()
	OnReset       func(reason byte, connID uint32)

	mu          sync.Mutex
	isn         uint16
	connID      uint32
	cap         uint16
	peerISN     uint16
	peerConnID  uint32
	peerMSS     uint16
	peerWindow  uint16
	havePeer    bool
	mySeq       uint16 // next seq to send
	peerExpect  uint16
	state       int
	established bool
	started     bool
	lastSyn     time.Time
	rto         time.Duration
	lastTx      time.Time
	unacked     []seg
	done        chan struct{}
}

type seg struct {
	seq     uint16
	payload []byte
	sent    time.Time
}

// New prepares a connection (does not send yet). isn/connID are the local handshake values.
func New(udp *net.UDPConn, peer *net.UDPAddr, isn uint16, connID uint32) *Conn {
	return &Conn{UDP: udp, Peer: peer, Port: 1, VPort: 1, isn: isn, connID: connID, cap: DefaultCap, mySeq: isn, state: stSynSent,
		rto: time.Second, done: make(chan struct{})}
}

func (c *Conn) synBlock() []byte {
	b := binary.BigEndian.AppendUint16(nil, c.cap)
	b = binary.BigEndian.AppendUint16(b, VerWord)
	b = binary.BigEndian.AppendUint16(b, VerWord)
	b = binary.BigEndian.AppendUint32(b, c.connID)
	return binary.BigEndian.AppendUint16(b, MSS)
}

func (c *Conn) synPacket() []byte {
	p := []byte{typeSyn << 6, WindowByte, byte(c.isn >> 8), byte(c.isn)}
	return append(p, c.synBlock()...)
}

func (c *Conn) synAckPacket() []byte {
	p := []byte{typeSyn<<6 | flagAck, WindowByte, byte(c.isn >> 8), byte(c.isn), byte(c.peerExpect >> 8), byte(c.peerExpect)}
	return append(p, c.synBlock()...)
}

// ackPacket is the empty acknowledgement: a data packet with the ack flag, seq = the next one to send (it consumes none).
func (c *Conn) ackPacket() []byte {
	return []byte{typeData<<6 | flagAck, WindowByte, byte(c.mySeq >> 8), byte(c.mySeq), byte(c.peerExpect >> 8), byte(c.peerExpect)}
}

func (c *Conn) dataPacket(s seg) []byte {
	p := []byte{typeData<<6 | flagAck, WindowByte, byte(s.seq >> 8), byte(s.seq), byte(c.peerExpect >> 8), byte(c.peerExpect)}
	return append(p, s.payload...)
}

// resetPacket is what librudp sends on a connect timeout (reason 3): window 0, seq 0, reason u16, our own connId.
func (c *Conn) resetPacket(reason byte) []byte {
	p := []byte{typeReset << 6, 0, 0, 0, 0, reason}
	return binary.BigEndian.AppendUint32(p, c.connID)
}

// Frame wraps one RUDP packet for the wire: class-2 aggregator frame, then the UDPP2P header.
func (c *Conn) Frame(pkt []byte) []byte {
	f := binary.BigEndian.AppendUint16(nil, 0x8000|uint16(4+len(pkt)))
	f = binary.BigEndian.AppendUint16(f, c.Port)
	return rtsig.Frame(rtsig.KindPlain, c.VPort, c.VPort, append(f, pkt...))
}

// send transmits one packet; the caller holds c.mu.
func (c *Conn) send(pkt []byte, now time.Time) {
	c.lastTx = now
	if c.Trace != nil {
		c.Trace("tx", Describe(pkt), pkt)
	}
	d := c.Frame(pkt)
	if c.Out != nil {
		c.Out(d)
		return
	}
	if c.UDP != nil && c.Peer != nil {
		c.UDP.WriteToUDP(d, c.Peer)
	}
}

func (c *Conn) note(dir, s string, b []byte) {
	if c.Trace != nil {
		c.Trace(dir, s, b)
	}
}

// Start sends the initial SYN (simultaneous open).
func (c *Conn) Start() error { c.StartAt(time.Now()); return nil }

// StartAt is Start with an explicit clock.
func (c *Conn) StartAt(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = true
	c.lastSyn = now
	c.send(c.synPacket(), now)
}

// Established reports the handshake state.
func (c *Conn) Established() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.established
}

// PeerMSS is the MSS in the peer's SYN block (0 before it).
func (c *Conn) PeerMSS() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerMSS
}

// Send queues one raw game payload (after ESTABLISHED); it is retransmitted until acked.
func (c *Conn) Send(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.established {
		return fmt.Errorf("rudp: not established")
	}
	s := seg{seq: c.mySeq, payload: append([]byte(nil), payload...), sent: time.Now()}
	c.mySeq++
	c.unacked = append(c.unacked, s)
	c.send(c.dataPacket(s), s.sent)
	return nil
}

// Tick drives retransmission: SYN and SYN+ACK on the 1, 2, 4, 8, 16 s schedule, unacked data after 1 s, a keepalive ack when idle.
func (c *Conn) Tick(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return
	}
	switch c.state {
	case stSynSent, stSynRcvd:
		if now.Sub(c.lastSyn) < c.rto {
			return
		}
		c.lastSyn = now
		if c.rto *= 2; c.rto > rtoMax {
			c.rto = rtoMax
		}
		if c.state == stSynSent {
			c.send(c.synPacket(), now)
		} else {
			c.send(c.synAckPacket(), now)
		}
	case stEstab:
		if len(c.unacked) > 0 && now.Sub(c.unacked[0].sent) >= time.Second {
			for i := range c.unacked {
				c.unacked[i].sent = now
				c.send(c.dataPacket(c.unacked[i]), now)
			}
		} else if now.Sub(c.lastTx) >= keepIdle {
			c.send(c.ackPacket(), now)
		}
	}
}

// RunTimers calls Tick every 250 ms until Close.
func (c *Conn) RunTimers() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-t.C:
			c.Tick(now)
		}
	}
}

// Close stops RunTimers and Serve.
func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

// pkt is one parsed RUDP packet.
type pkt struct {
	typ, flags, window byte
	seq, ack, ts       uint16
	off                int // payload offset (after type block and options)
	cap, verA, verB    uint16
	connID             uint32
	mss                uint16
	reason             byte
}

// parse reads a packet in librudp's order (FUN_0000ddb8): header, window, seq, ack, ts, type block, options, payload.
func parse(p []byte) (k pkt, err error) {
	if len(p) < 4 {
		return k, fmt.Errorf("short packet")
	}
	k.typ, k.flags, k.window = p[0]>>6, p[0]&0x3f, p[1]
	k.seq = binary.BigEndian.Uint16(p[2:])
	off := 4
	if k.flags&flagAck != 0 {
		if len(p) < off+2 {
			return k, fmt.Errorf("short ack")
		}
		k.ack = binary.BigEndian.Uint16(p[off:])
		off += 2
	}
	if k.flags&flagTS != 0 {
		if k.flags&flagAck == 0 || len(p) < off+2 {
			return k, fmt.Errorf("timestamp without ack or short")
		}
		k.ts = binary.BigEndian.Uint16(p[off:])
		off += 2
	}
	switch k.typ {
	case typeSyn:
		if len(p) < off+12 {
			return k, fmt.Errorf("short SYN block")
		}
		k.cap, k.verA, k.verB = binary.BigEndian.Uint16(p[off:]), binary.BigEndian.Uint16(p[off+2:]), binary.BigEndian.Uint16(p[off+4:])
		k.connID, k.mss = binary.BigEndian.Uint32(p[off+6:]), binary.BigEndian.Uint16(p[off+10:])
		off += 12
	case typeReset:
		if len(p) < off+6 {
			return k, fmt.Errorf("short reset block")
		}
		k.reason, k.connID = p[off+1], binary.BigEndian.Uint32(p[off+2:])
		off += 6
	}
	if k.flags&flagOpts != 0 {
		for off < len(p) {
			t := p[off]
			off++
			if t&0x7f != 0 {
				if off >= len(p) {
					return k, fmt.Errorf("short option")
				}
				off += 1 + int(p[off])
			}
			if t&0x80 != 0 {
				break
			}
		}
	}
	if off > len(p) {
		return k, fmt.Errorf("options overrun")
	}
	k.off = off
	return k, nil
}

// Describe is the one-line form of an RUDP packet for the recorder.
func Describe(p []byte) string {
	k, err := parse(p)
	if err != nil {
		return fmt.Sprintf("unparsable (%v) %x", err, p)
	}
	name := [...]string{"DATA", "ACK", "SYN", "RESET"}[k.typ]
	if k.typ == typeSyn && k.flags&flagAck != 0 {
		name = "SYN+ACK"
	}
	s := fmt.Sprintf("%s flags=%#02x win=%#02x seq=%#04x", name, k.flags, k.window, k.seq)
	if k.flags&flagAck != 0 {
		s += fmt.Sprintf(" ack=%#04x", k.ack)
	}
	switch k.typ {
	case typeSyn:
		s += fmt.Sprintf(" cap=%#04x verA=%#04x verB=%#04x connid=%#08x mss=%d", k.cap, k.verA, k.verB, k.connID, k.mss)
	case typeReset:
		s += fmt.Sprintf(" reason=%d connid=%#08x", k.reason, k.connID)
	}
	if k.off < len(p) {
		s += fmt.Sprintf(" payload(%d)=%x", len(p)-k.off, p[k.off:])
	}
	return s
}

func after(a, b uint16) bool { return int16(a-b) > 0 }

// HandleDatagram feeds one received UDP datagram (with its UDPP2P header) into the connection. A bad datagram ends that datagram only.
func (c *Conn) HandleDatagram(d []byte) error {
	kind, src, dst, body, err := rtsig.Unframe(d)
	if err != nil {
		c.note("rx", fmt.Sprintf("not a UDPP2P datagram: %x", d), d)
		return err
	}
	if kind >= 7 && kind <= 10 {
		c.note("rx", fmt.Sprintf("kernel unreachable reply kind %d (the peer's vport is not bound)", kind), d)
		return nil
	}
	c.note("rx", fmt.Sprintf("udpp2p kind=%d vport %#x->%#x %d bytes", kind, src, dst, len(d)), d)
	var estab bool
	var reset *pkt
	var deliver [][]byte
	c.mu.Lock()
	for len(body) >= 2 {
		h := binary.BigEndian.Uint16(body)
		class, l := h>>14, int(h&0x7ff)
		if l < 2 || l > len(body) {
			c.note("rx", fmt.Sprintf("bad frame length %d of %d", l, len(body)), body)
			err = fmt.Errorf("rudp: bad frame length %d", l)
			break
		}
		p := body[2:l]
		body = body[l:]
		switch class {
		case 1:
		case 2:
			if len(p) < 2 {
				c.note("rx", "short class-2 frame", p)
				continue
			}
			if port := binary.BigEndian.Uint16(p); port != c.Port {
				c.note("rx", fmt.Sprintf("frame for rudp port %d (ours %d), ignored", port, c.Port), p)
				continue
			}
			p = p[2:]
		case 3:
			if len(p) < 4 {
				c.note("rx", "short class-3 frame", p)
				continue
			}
			p = p[4:]
		default:
			c.note("rx", fmt.Sprintf("class %d frame, ignored", class), p)
			continue
		}
		e, r, dl := c.handlePacket(p, time.Now())
		estab = estab || e
		if r != nil {
			reset = r
		}
		deliver = append(deliver, dl...)
	}
	c.mu.Unlock()
	if estab && c.OnEstablished != nil {
		c.OnEstablished()
	}
	for _, p := range deliver {
		if c.OnPayload != nil {
			c.OnPayload(p)
		}
	}
	if reset != nil && c.OnReset != nil {
		c.OnReset(reset.reason, reset.connID)
	}
	return err
}

func (c *Conn) establish() {
	c.established, c.state = true, stEstab
	c.mySeq = c.isn + 1
}

// handlePacket applies one packet; the caller holds c.mu.
func (c *Conn) handlePacket(p []byte, now time.Time) (estab bool, reset *pkt, deliver [][]byte) {
	k, err := parse(p)
	if err != nil {
		c.note("rx", fmt.Sprintf("unparsable packet (%v) %x", err, p), p)
		return
	}
	c.note("rx", Describe(p), p)
	switch k.typ {
	case typeSyn:
		if k.verA < VerWord || k.verB > VerWord {
			c.note("rx", "SYN version words refused (librudp aborts locally, reason 4)", p)
			return
		}
		c.cap = k.cap // the console's own flags: its check wants ours equal
		if k.flags&flagAck != 0 {
			if k.ack != c.isn+1 {
				c.note("rx", fmt.Sprintf("SYN+ACK acks %#04x, want %#04x: ignored (librudp aborts locally, reason 2)", k.ack, c.isn+1), p)
				return
			}
			c.takePeer(k)
			if !c.established {
				c.establish()
				estab = true
			}
			c.send(c.ackPacket(), now) // completes the peer's SYN-RECEIVED (seq = our ISN+1, it consumes none)
			return
		}
		if c.havePeer && k.connID != c.peerConnID {
			c.note("rx", fmt.Sprintf("SYN from another connection id %#08x (ours peer %#08x): answered anyway", k.connID, c.peerConnID), p)
		}
		c.takePeer(k)
		if c.state == stSynSent {
			c.state = stSynRcvd
			c.lastSyn = now
		}
		c.send(c.synAckPacket(), now) // also while established: the peer may not have our SYN+ACK yet
	case typeData, typeAck:
		if k.flags&flagAck != 0 {
			if c.state == stSynRcvd && k.typ == typeData && k.ack == c.isn+1 {
				c.establish()
				estab = true
			}
			for len(c.unacked) > 0 && after(k.ack, c.unacked[0].seq) {
				c.unacked = c.unacked[1:]
			}
		}
		if k.typ == typeData && k.off < len(p) {
			if k.seq == c.peerExpect {
				c.peerExpect++
				deliver = append(deliver, append([]byte(nil), p[k.off:]...))
			} else {
				c.note("rx", fmt.Sprintf("data seq %#04x, expected %#04x: re-acked", k.seq, c.peerExpect), p)
			}
			c.send(c.ackPacket(), now)
		}
	case typeReset:
		c.note("rx", fmt.Sprintf("RESET reason %d from connid %#08x: connection closed by the peer", k.reason, k.connID), p)
		c.state, c.established = stClosed, false
		kk := k
		reset = &kk
	}
	return
}

func (c *Conn) takePeer(k pkt) {
	c.peerISN, c.peerConnID, c.peerMSS, c.peerWindow = k.seq, k.connID, k.mss, uint16(k.window&0x3f)<<((k.window>>5)&6)
	if !c.havePeer {
		c.havePeer = true
		c.peerExpect = k.seq + 1
	}
}

// Serve reads datagrams from the socket until it errors, running the timers meanwhile (tests; the probe reads the socket itself).
func (c *Conn) Serve() error {
	go c.RunTimers()
	buf := make([]byte, 4096)
	for {
		c.UDP.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _, err := c.UDP.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		// a bad datagram ends itself, not the connection
		c.HandleDatagram(append([]byte(nil), buf[:n]...))
	}
}
