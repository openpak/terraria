// Package rudp is the cellRudp wire protocol (Sony librudp) as a Terraria peer speaks it: simultaneous
// SYN/SYN+ACK open, then raw payloads. Layout from the librudp decompile (research notes §26):
// a UDP datagram is a sequence of aggregator frames (u16: class<<14 | length-incl-header); each frame
// payload is one RUDP packet (type<<6|flags, window, seq, [ack], [ts], type block, payload). No checksum.
package rudp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	frameClass1 = 0x4000
	flagAck     = 0x20
	flagOpts    = 0x10
	flagTS      = 0x04
	windowByte  = 0xff // (0xff&0x3f) << ((0xff>>6)*2) = 4032
	mss         = 1200
)

// Conn is one RUDP peer connection over an existing UDP socket.
type Conn struct {
	UDP  *net.UDPConn
	Peer *net.UDPAddr

	OnPayload     func([]byte)
	OnEstablished func()

	mu          sync.Mutex
	isn         uint16
	connID      uint32
	peerISN     uint16
	peerConnID  uint32
	mySeq       uint16 // next seq to send
	peerExpect  uint16
	state       int // 2 syn-sent, 3 syn-received, 4 established
	established bool
	lastSyn     time.Time
}

// New prepares a connection (does not send yet). isn/connID are the local handshake values.
func New(udp *net.UDPConn, peer *net.UDPAddr, isn uint16, connID uint32) *Conn {
	return &Conn{UDP: udp, Peer: peer, isn: isn, connID: connID, mySeq: isn, state: 2}
}

func synPacket(seq uint16, connID uint32) []byte {
	p := []byte{0x80, windowByte, byte(seq >> 8), byte(seq)}
	p = binary.BigEndian.AppendUint16(p, 0)      // capWord
	p = binary.BigEndian.AppendUint16(p, 0x0100) // verA
	p = binary.BigEndian.AppendUint16(p, 0x0100) // verB
	p = binary.BigEndian.AppendUint32(p, connID)
	p = binary.BigEndian.AppendUint16(p, mss)
	return p
}

func synAckPacket(seq, ack uint16, connID uint32) []byte {
	p := []byte{0x80 | flagAck, windowByte, byte(seq >> 8), byte(seq), byte(ack >> 8), byte(ack)}
	p = binary.BigEndian.AppendUint16(p, 0)
	p = binary.BigEndian.AppendUint16(p, 0x0100)
	p = binary.BigEndian.AppendUint16(p, 0x0100)
	p = binary.BigEndian.AppendUint32(p, connID)
	p = binary.BigEndian.AppendUint16(p, mss)
	return p
}

func ackPacket(seq, ack uint16) []byte {
	return []byte{flagAck, windowByte, byte(seq >> 8), byte(seq), byte(ack >> 8), byte(ack)}
}

func frame(payload []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(frameClass1|(2+len(payload))))
	return append(out, payload...)
}

func (c *Conn) send(pkt []byte) error {
	_, err := c.UDP.WriteToUDP(frame(pkt), c.Peer)
	return err
}

// Start sends the initial SYN (simultaneous open).
func (c *Conn) Start() error {
	c.mu.Lock()
	c.lastSyn = time.Now()
	c.mu.Unlock()
	return c.send(synPacket(c.isn, c.connID))
}

func (c *Conn) markEstablished() {
	c.mu.Lock()
	if c.established {
		c.mu.Unlock()
		return
	}
	c.established, c.state = true, 4
	c.mySeq = c.isn + 1
	cb := c.OnEstablished
	c.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// Send queues one raw game payload (after ESTABLISHED).
func (c *Conn) Send(payload []byte) error {
	c.mu.Lock()
	if !c.established {
		c.mu.Unlock()
		return fmt.Errorf("rudp: not established")
	}
	pkt := []byte{flagAck, windowByte, byte(c.mySeq >> 8), byte(c.mySeq), byte(c.peerExpect >> 8), byte(c.peerExpect)}
	c.mySeq++
	c.mu.Unlock()
	return c.send(append(pkt, payload...))
}

// Established reports the handshake state.
func (c *Conn) Established() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.established
}

// header parses one RUDP packet and returns type, flags, seq, ack and the payload offset.
func parsePacket(p []byte) (typ byte, flags byte, seq, ack uint16, off int, err error) {
	if len(p) < 4 {
		return 0, 0, 0, 0, 0, fmt.Errorf("rudp: short packet")
	}
	typ, flags = p[0]>>6, p[0]&0x3f
	seq = binary.BigEndian.Uint16(p[2:])
	off = 4
	if flags&flagAck != 0 {
		if len(p) < off+2 {
			return 0, 0, 0, 0, 0, fmt.Errorf("rudp: short ack")
		}
		ack = binary.BigEndian.Uint16(p[off:])
		off += 2
	}
	if flags&flagTS != 0 {
		off += 2
	}
	if flags&flagOpts != 0 {
		for off < len(p) {
			t := p[off]
			off++
			if t == 0 {
				break
			}
			if off >= len(p) {
				return 0, 0, 0, 0, 0, fmt.Errorf("rudp: short option")
			}
			l := int(p[off])
			off += 1 + l
			if t&0x80 == 0 {
				break
			}
		}
	}
	if off > len(p) {
		return 0, 0, 0, 0, 0, fmt.Errorf("rudp: options overrun")
	}
	return typ, flags, seq, ack, off, nil
}

// HandleDatagram feeds one received UDP datagram into the connection.
func (c *Conn) HandleDatagram(d []byte) error {
	for len(d) >= 2 {
		h := binary.BigEndian.Uint16(d)
		class, l := h>>14, int(h&0x7ff)
		if l < 2 || l > len(d) {
			return fmt.Errorf("rudp: bad frame length %d", l)
		}
		p := d[2:l]
		switch class {
		case 1:
		case 2:
			if len(p) < 2 {
				return fmt.Errorf("rudp: short class2")
			}
			p = p[2:]
		case 3:
			if len(p) < 4 {
				return fmt.Errorf("rudp: short class3")
			}
			p = p[4:]
		default:
			return fmt.Errorf("rudp: bad class %d", class)
		}
		if err := c.handlePacket(p); err != nil {
			return err
		}
		d = d[l:]
	}
	return nil
}

func (c *Conn) handlePacket(p []byte) error {
	typ, flags, seq, ack, off, err := parsePacket(p)
	if err != nil {
		return err
	}
	c.mu.Lock()
	state := c.state
	c.mu.Unlock()
	switch typ {
	case 2: // SYN or SYN+ACK
		if off+12 > len(p) {
			return fmt.Errorf("rudp: short syn")
		}
		connID := binary.BigEndian.Uint32(p[off+6:])
		c.mu.Lock()
		c.peerISN, c.peerConnID, c.peerExpect = seq, connID, seq+1
		st := c.state
		c.mu.Unlock()
		if flags&flagAck != 0 {
			if ack != c.isn+1 {
				return fmt.Errorf("rudp: synack ack %d, want %d", ack, c.isn+1)
			}
			// ESTABLISHED; complete a state-3 peer with an empty DATA-ACK below.
			c.send(ackPacket(c.isn+1, seq+1))
			c.markEstablished()
			_ = st
			return nil
		}
		if state == 2 || state == 3 {
			return c.send(synAckPacket(c.isn, seq+1, c.connID))
		}
		return nil
	case 0: // DATA (also the handshake-completing DATA-ACK in state 3)
		c.mu.Lock()
		c.peerExpect = seq + 1
		est := c.established
		c.mu.Unlock()
		if !est && flags&flagAck != 0 {
			c.markEstablished()
		}
		if off < len(p) && c.OnPayload != nil {
			c.OnPayload(append([]byte(nil), p[off:]...))
		}
		return nil
	case 3: // RESET
		return fmt.Errorf("rudp: reset by peer")
	}
	return nil
}

// Serve reads datagrams until the socket errors; it retransmits the SYN every 3s until established.
func (c *Conn) Serve() error {
	go func() {
		for {
			time.Sleep(3 * time.Second)
			c.mu.Lock()
			done := c.established
			c.mu.Unlock()
			if done {
				return
			}
			c.send(synPacket(c.isn, c.connID))
		}
	}()
	buf := make([]byte, 4096)
	for {
		c.UDP.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _, err := c.UDP.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if err := c.HandleDatagram(append([]byte(nil), buf[:n]...)); err != nil {
			// keep serving: a bad packet ends one datagram, not the connection
			continue
		}
	}
}
