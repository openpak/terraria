package rtsig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// The signaling UDP probe, 0x58 bytes (vsh 4.93 builder FUN_001ea168, parser FUN_001e9518):
//
//	+0x00 type: 1 request, 2 response, 3 data (RTT); 4/5 are short forms
//	+0x04 sender's own NpId (32-byte probe form, see NpIDFromJID)
//	+0x24 sender's peer NpId
//	+0x44 sender's sid, +0x46 peer sid
//	+0x48 u64 send time (type 1), echoed by type 2
//	+0x50 type 2: requester's IPv4 as the responder saw it, XOR the u32 at +0x44
//	+0x54 type 2: requester's port, XOR the u16 at +0x44
//
// The receiver looks its connection up with sceNpUtilCmpNpId (FUN_001f79bc): packet +0x24 against its own
// NpId, +0x04 against its peer's. The compare fails unless reserved[0] == 1 on both sides and opt[0..4]
// match exactly, so a probe without proper NpIds is dropped silently.
const probeLen = 0x58

// NpIDFromJID returns the probe form of the NpId vsh builds from an RT JID (FUN_001f9024 / FUN_001f8d98):
// online id (16, NUL padded), opt = domain labels 1 and 2 (2 chars each) + resource (<= 4 chars),
// reserved[0] = 1. "SwitchTest@us.us.np.playstation.net/ps3" -> "SwitchTest", "ususps3\0", 01 00...
func NpIDFromJID(jid string) ([]byte, error) {
	node, rest, ok := strings.Cut(jid, "@")
	domain, res, _ := strings.Cut(rest, "/")
	if !ok || len(node) == 0 || len(node) > 16 || len(res) > 4 || len(domain) < 6 || domain[2] != '.' || domain[5] != '.' {
		return nil, errors.New("rtsig: not an NP JID: " + jid)
	}
	b := make([]byte, 32)
	copy(b, node)
	copy(b[16:], domain[0:2])
	copy(b[18:], domain[3:5])
	copy(b[20:], res)
	b[24] = 1
	return b, nil
}

// ProbePacket builds a type-1 probe from our connection: own NpId at +0x04, peer NpId at +0x24.
func ProbePacket(ownNpID, peerNpID []byte, ownSID, peerSID uint16, now uint64) []byte {
	out := make([]byte, probeLen)
	out[0] = 1
	copy(out[0x04:0x24], ownNpID)
	copy(out[0x24:0x44], peerNpID)
	binary.BigEndian.PutUint16(out[0x44:], ownSID)
	binary.BigEndian.PutUint16(out[0x46:], peerSID)
	binary.BigEndian.PutUint64(out[0x48:], now)
	return out
}

// ProbeResponsePacket answers a type-1 request received from src (vsh event 0x10 path): our NpIds and
// sids, the request's +0x48 time echoed, and src (the requester's mapped endpoint) XORed with our sid pair.
func ProbeResponsePacket(req []byte, src *net.UDPAddr, ownNpID, peerNpID []byte, ownSID, peerSID uint16) []byte {
	ip := src.IP.To4()
	if len(req) < probeLen || req[0] != 1 || ip == nil {
		return nil
	}
	out := ProbePacket(ownNpID, peerNpID, ownSID, peerSID, binary.BigEndian.Uint64(req[0x48:]))
	out[0] = 2
	binary.BigEndian.PutUint32(out[0x50:], binary.BigEndian.Uint32(ip)^(uint32(ownSID)<<16|uint32(peerSID)))
	binary.BigEndian.PutUint16(out[0x54:], uint16(src.Port)^ownSID)
	return out
}

// ProbeFrom reports whether body is a probe the peer sent to us (its NpId at +0x04, ours at +0x24). Our
// own probes hairpinned back by a shared NAT carry our NpId at +0x04 and are rejected.
func ProbeFrom(body, ownNpID, peerNpID []byte) bool {
	return len(body) >= probeLen && body[0] >= 1 && body[0] <= 3 &&
		bytes.Equal(body[0x04:0x24], peerNpID) && bytes.Equal(body[0x24:0x44], ownNpID)
}

// ProbeMapped decodes a type-2 response: our endpoint as the responder saw it.
func ProbeMapped(resp []byte) *net.UDPAddr {
	if len(resp) < probeLen || resp[0] != 2 {
		return nil
	}
	pair := binary.BigEndian.Uint32(resp[0x44:])
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(resp[0x50:])^pair)
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(resp[0x54:]) ^ uint16(pair>>16))}
}
