package pia

import "encoding/binary"

// Mesh ("session" in PIA 3.x) protocol 0x0200, as Terraria (Wii U) sends it on port 0. Layouts from the wiki's Mesh Protocol page
// ("up to 5.10" join request, "up to 3.10" join response).
const (
	MeshJoinReq  = 0x01
	MeshJoinResp = 0x02
	MeshLeaveReq = 0x04
	MeshLeave    = 0x08
	MeshUpdate   = 0x20
)

// JoinRequest is a mesh join request: the joiner's station index (0xFD before it has one), its address and an ack id.
type JoinRequest struct {
	StationIndex uint8
	Addr         []byte // 8-byte StationAddress
	AckID        uint32
}

func ParseJoinRequest(p []byte) (JoinRequest, bool) {
	if len(p) < 16 || p[0] != MeshJoinReq {
		return JoinRequest{}, false
	}
	return JoinRequest{StationIndex: p[1], Addr: append([]byte(nil), p[4:12]...), AckID: binary.BigEndian.Uint32(p[12:])}, true
}

// MeshStation is one StationInfo entry: the station's connection info and its index in the mesh.
type MeshStation struct {
	Public, Private StationLocation
	Index           uint8
}

// JoinResponse builds an accepted join response (3.x): every station of the mesh in one fragment.
func JoinResponse(hostIndex, joinerIndex uint8, stations []MeshStation, ackID uint32) []byte {
	b := []byte{MeshJoinResp, uint8(len(stations)), hostIndex, joinerIndex, 1, 0, uint8(len(stations)), 0}
	for _, s := range stations {
		start := len(b)
		b = s.Public.append(b)
		b = s.Private.append(b)
		b = append(b, s.Index)
		for (len(b)-start)%4 != 0 {
			b = append(b, 0)
		}
	}
	return binary.BigEndian.AppendUint32(b, ackID)
}
