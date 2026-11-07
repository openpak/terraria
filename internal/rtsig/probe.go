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
		pkt := append([]byte(nil), buf[:n]...)
		if l.OnPeer != nil {
			l.OnPeer(src, pkt)
		}
		if resp := ProbeResponse(pkt, l.SID); resp != nil {
			l.Conn.WriteToUDP(resp, src)
		}
	}
}
