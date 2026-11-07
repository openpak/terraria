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

func appendStations(b []byte, stations []MeshStation) []byte {
	for _, s := range stations {
		start := len(b)
		b = s.Public.append(b)
		b = s.Private.append(b)
		b = append(b, s.Index)
		for (len(b)-start)%4 != 0 {
			b = append(b, 0)
		}
	}
	return b
}

// UpdateMesh builds an update-mesh message (0x20): every station of the mesh, one fragment.
func UpdateMesh(hostIndex uint8, counter uint32, stations []MeshStation) []byte {
	b := []byte{MeshUpdate, uint8(len(stations)), hostIndex, 0}
	b = binary.BigEndian.AppendUint32(b, counter)
	b = append(b, 1, 0, uint8(len(stations)), 0)
	return appendStations(b, stations)
}

// JoinResponse builds an accepted join response (3.x): every station of the mesh in one fragment.
func JoinResponse(hostIndex, joinerIndex uint8, stations []MeshStation, ackID uint32) []byte {
	b := []byte{MeshJoinResp, uint8(len(stations)), hostIndex, joinerIndex, 1, 0, uint8(len(stations)), 0}
	b = appendStations(b, stations)
	return binary.BigEndian.AppendUint32(b, ackID)
}

// JoinRequestMessage builds a mesh join request from a joiner that has no station index yet (0xFD).
func JoinRequestMessage(addr StationLocation, ackID uint32) []byte {
	b := []byte{MeshJoinReq, 0xfd, 0, 0}
	b = addr.append(b)[:4+8] // the StationAddress part only: ip, port, extension
	return binary.BigEndian.AppendUint32(b, ackID)
}
