package pia

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf16"
)

// Station protocol (protocol 0x0100, port 0) as PIA 3.7-3.10 speaks it (station version 3), from the wiki's Station Protocol page
// and confirmed against Terraria (Wii U) in Quay. Message types are the first payload byte.
const (
	StationConnReq   = 1
	StationConnResp  = 2
	StationDiscReq   = 3
	StationDiscResp  = 4
	StationAck       = 5
	StationVersion3  = 3
	PlatformWiiU     = 3
	StationLocLen    = 27
	stationConnInfoN = 2 * StationLocLen
	playerInfoLen    = 36
	tokenLen         = 32
)

// StationLocation is the 27-byte location of PIA 3.x/4.x: address, extension id, PID, CID, RVCID and the NAT/URL fields.
type StationLocation struct {
	Addr       netip.AddrPort
	Extension  uint16
	PID        uint32
	CID        uint32
	RVCID      uint32
	URLType    uint8
	SID        uint8
	StreamType uint8
	NATMapping uint8
	NATFilter  uint8
	NATType    uint8
	ProbeInit  uint8
}

func (l StationLocation) append(b []byte) []byte {
	var ip [4]byte
	if l.Addr.Addr().Is4() {
		ip = l.Addr.Addr().As4()
	}
	b = append(b, ip[:]...)
	b = binary.BigEndian.AppendUint16(b, l.Addr.Port())
	b = binary.BigEndian.AppendUint16(b, l.Extension)
	b = binary.BigEndian.AppendUint32(b, l.PID)
	b = binary.BigEndian.AppendUint32(b, l.CID)
	b = binary.BigEndian.AppendUint32(b, l.RVCID)
	return append(b, l.URLType, l.SID, l.StreamType, l.NATMapping, l.NATFilter, l.NATType, l.ProbeInit)
}

func parseLocation(b []byte) StationLocation {
	return StationLocation{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[0:4])), binary.BigEndian.Uint16(b[4:])),
		Extension: binary.BigEndian.Uint16(b[6:]), PID: binary.BigEndian.Uint32(b[8:]), CID: binary.BigEndian.Uint32(b[12:]),
		RVCID: binary.BigEndian.Uint32(b[16:]), URLType: b[20], SID: b[21], StreamType: b[22], NATMapping: b[23], NATFilter: b[24],
		NATType: b[25], ProbeInit: b[26]}
}

// ConnRequest is a station connection request (or its inverse).
type ConnRequest struct {
	ConnID  uint8
	Version uint8
	Inverse bool
	Public  StationLocation
	Private StationLocation
	AckID   uint32
}

func (r ConnRequest) Marshal() []byte {
	inv := uint8(0)
	if r.Inverse {
		inv = 1
	}
	b := []byte{StationConnReq, r.ConnID, r.Version, inv}
	b = r.Public.append(b)
	b = r.Private.append(b)
	return binary.BigEndian.AppendUint32(b, r.AckID)
}

// PlayerInfo is the 3.x player info: name (UTF-16, up to 16 units), language.
type PlayerInfo struct {
	Name     string
	Language uint8
}

func (p PlayerInfo) append(b []byte) []byte {
	u := utf16.Encode([]rune(p.Name))
	if len(u) > 16 {
		u = u[:16]
	}
	name := make([]byte, 32)
	for i, c := range u {
		binary.BigEndian.PutUint16(name[2*i:], c)
	}
	b = append(b, name...)
	return append(b, uint8(len(u)), p.Language, 0, 0)
}

func parsePlayerInfo(b []byte) PlayerInfo {
	n := int(b[32])
	if n > 16 {
		n = 16
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(b[2*i:])
	}
	return PlayerInfo{Name: string(utf16.Decode(u)), Language: b[33]}
}

// ConnResponse is a station connection response.
type ConnResponse struct {
	Result   uint8
	Version  uint8
	Platform uint8
	Token    string
	Player   PlayerInfo
	AckID    uint32
}

func (r ConnResponse) Marshal() []byte {
	b := []byte{StationConnResp, r.Result, r.Version, r.Platform}
	if r.Result != 0 {
		b[3] = 0
		return b
	}
	tok := make([]byte, tokenLen)
	copy(tok, r.Token)
	b = append(b, tok...)
	b = r.Player.append(b)
	return binary.BigEndian.AppendUint32(b, r.AckID)
}

// AckMessage acknowledges ackID.
func AckMessage(ackID uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte{StationAck, 0, 0, 0}, ackID)
}

// StationMsg is one decoded station-protocol payload.
type StationMsg struct {
	Type     uint8
	Request  *ConnRequest
	Response *ConnResponse
	AckID    uint32 // for StationAck
}

var ErrStation = errors.New("pia: bad station message")

// ParseStation decodes a station-protocol payload (version 3 layouts).
func ParseStation(p []byte) (*StationMsg, error) {
	if len(p) < 1 {
		return nil, ErrStation
	}
	m := &StationMsg{Type: p[0]}
	switch p[0] {
	case StationConnReq:
		if len(p) < 4+stationConnInfoN+4 {
			return m, fmt.Errorf("%w: connection request of %d bytes", ErrStation, len(p))
		}
		m.Request = &ConnRequest{ConnID: p[1], Version: p[2], Inverse: p[3] != 0, Public: parseLocation(p[4:]),
			Private: parseLocation(p[4+StationLocLen:]), AckID: binary.BigEndian.Uint32(p[4+stationConnInfoN:])}
	case StationConnResp:
		if len(p) < 4 {
			return m, ErrStation
		}
		r := &ConnResponse{Result: p[1], Version: p[2], Platform: p[3]}
		m.Response = r
		if r.Result == 0 {
			if len(p) < 4+tokenLen+playerInfoLen+4 {
				return m, fmt.Errorf("%w: connection response of %d bytes", ErrStation, len(p))
			}
			tok := p[4 : 4+tokenLen]
			for i, c := range tok {
				if c == 0 {
					tok = tok[:i]
					break
				}
			}
			r.Token = string(tok)
			r.Player = parsePlayerInfo(p[4+tokenLen:])
			r.AckID = binary.BigEndian.Uint32(p[4+tokenLen+playerInfoLen:])
		}
	case StationAck:
		if len(p) < 8 {
			return m, ErrStation
		}
		m.AckID = binary.BigEndian.Uint32(p[4:])
	}
	return m, nil
}
