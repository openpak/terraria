package rtsig

import (
	"encoding/binary"
	"net"
	"time"
)

// The signaling UDP probe (vsh FUN_001ea168): 0x58-byte packets, byte 0 = type (1 request, 2 response,
// 3 data). The receiver validates identity fields copied from the connection and, for type 2, a u32 at
// +0x50 equal to a received field XOR the connection's sid. The exact validated offsets are not fully
// decoded, so the responder echoes the request's identity fields verbatim and XORs the +0x50 field with
// our sid [I]; every probe is logged by the caller for live iteration.
const probeLen = 0x58

// ProbePacket builds a type-1 probe (vsh FUN_001ea168): peer skey at +0x04, own skey at +0x24,
// own sid at +0x44 and peer sid at +0x46 (the builder copies conn+0x10/+0x34/+0x58/+0x5a).
func ProbePacket(ownSKey, peerSKey []byte, ownSID, peerSID uint16) []byte {
	out := make([]byte, probeLen)
	out[0] = 1
	copy(out[0x04:0x14], peerSKey)
	copy(out[0x24:0x34], ownSKey)
	binary.BigEndian.PutUint16(out[0x44:], ownSID)
	binary.BigEndian.PutUint16(out[0x46:], peerSID)
	return out
}

// ProbeResponse builds the type-2 answer to a type-1 probe from cand.
func ProbeResponse(req []byte, ownSID uint16) []byte {
	if len(req) < probeLen || req[0] != 1 {
		return nil
	}
	out := append([]byte(nil), req[:probeLen]...)
	out[0] = 2
	v := binary.BigEndian.Uint32(out[0x50:])
	binary.BigEndian.PutUint32(out[0x50:], v^uint32(ownSID))
	return out
}

// ProbeResponsePacket builds the type-2 answer from our own connection fields (vsh FUN_001ea168):
// our skey at +0x04, the peer's at +0x24, our sid at +0x44, the peer's at +0x46, the request's
// +0x48 timestamps echoed, and the +0x50/+0x54 fields XORed with our sid.
func ProbeResponsePacket(req []byte, ownSKey, peerSKey []byte, ownSID, peerSID uint16) []byte {
	if len(req) < probeLen || req[0] != 1 {
		return nil
	}
	out := ProbePacket(ownSKey, peerSKey, ownSID, peerSID)
	out[0] = 2
	copy(out[0x48:0x50], req[0x48:0x50])
	// The validator un-XORs +0x50 with the packet's own +0x44 sid pair (vsh FUN_001e9518).
	binary.BigEndian.PutUint32(out[0x50:], binary.BigEndian.Uint32(req[0x50:])^binary.BigEndian.Uint32(out[0x44:]))
	binary.BigEndian.PutUint16(out[0x54:], binary.BigEndian.Uint16(req[0x54:])^ownSID)
	return out
}

// ProbeListener answers host probes on the participant endpoint and reports the first probe source.
type ProbeListener struct {
	Conn   *net.UDPConn
	SID    uint16
	OnPeer func(src *net.UDPAddr, req []byte)
}

// Serve answers probes until the connection closes; resolve/keepalive traffic is the caller's log.
func (l *ProbeListener) Serve() {
	buf := make([]byte, 2048)
	for {
		l.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, src, err := l.Conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Real consoles frame every datagram (UDPP2P); unframed packets are still passed to OnPeer
		// so a framing mismatch shows up in the log, but only framed probes are answered.
		pkt := append([]byte(nil), buf[:n]...)
		if l.OnPeer != nil {
			l.OnPeer(src, pkt)
		}
		if _, _, _, body, err := Unframe(pkt); err == nil {
			if resp := ProbeResponse(body, l.SID); resp != nil {
				l.Conn.WriteToUDP(FrameSignal(resp), src)
			}
		}
	}
}
