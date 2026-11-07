package relay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/openpak/terraria/internal/pia"
)

// hostLeg answers a Wii U's station handshake as the host it thinks it is joining (relay leg W, prds#145): ack its connection
// request, send the inverse request, ack its connection response and answer with ours. Everything it sends is captured.
type hostLeg struct {
	mu      sync.Mutex
	conn    net.PacketConn
	key     []byte
	pid     uint32
	self    netip.AddrPort
	capture func(raw []byte, peer string, out bool) // optional: records every packet
	// OnGame receives every Terraria message the console sends (the relay forwards it to the other leg).
	OnGame func(peer string, msg []byte)
	// Greet makes the leg act as the Terraria host itself (PlayerId, request player info): test mode, no other leg.
	Greet   bool
	stats   Stats
	start   time.Time
	ours    map[string]uint32 // peer -> ack id of our inverse request
	done    map[string]bool   // peer -> our response sent
	info    map[string]*pia.ConnRequest
	conn1   map[string]uint8  // peer -> connection id it uses once connected (packet header)
	pkt     map[string]uint16 // peer -> our next packet id
	rel     map[string]*relState
	joinAck map[string]uint32
}

// relState is one peer's reliable stream: our next sequence, what we expect next, unacked data to resend.
type relState struct {
	sendSeq, recvNext uint32
	hello             bool
	pending           map[uint32][]byte
	last              time.Time
}

// Stats are a leg's counters.
type Stats struct{ PacketsIn, PacketsOut, GameIn int64 }

func newHostLeg(conn net.PacketConn, key []byte, pid uint32, self netip.AddrPort, capture func([]byte, string, bool)) *hostLeg {
	return &hostLeg{conn: conn, key: key, pid: pid, self: self, capture: capture, start: time.Now(), ours: map[string]uint32{}, done: map[string]bool{}, info: map[string]*pia.ConnRequest{}, conn1: map[string]uint8{}, pkt: map[string]uint16{}, rel: map[string]*relState{}, joinAck: map[string]uint32{}}
}

func rnd32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (h *hostLeg) location(natType uint8) pia.StationLocation {
	return pia.StationLocation{Addr: h.self, PID: h.pid, RVCID: 1, URLType: 1, SID: 0x0f, NATMapping: 1, NATFilter: 2, NATType: natType}
}

func (h *hostLeg) send(to net.Addr, theirTimer uint16, payloads ...[]byte) {
	h.sendProto(to, theirTimer, pia.ProtoStation, 0xfd, payloads...)
}

func (h *hostLeg) sendProto(to net.Addr, theirTimer uint16, proto uint16, src uint8, payloads ...[]byte) {
	var msgs []pia.Message
	for _, p := range payloads {
		msgs = append(msgs, pia.Message{SrcStation: src, Protocol: proto, Payload: p})
	}
	h.sendMsgs(to, theirTimer, msgs)
}

// sendMsgs sends messages; once the peer uses a connection id, packets carry it and a rising packet id.
func (h *hostLeg) sendMsgs(to net.Addr, theirTimer uint16, msgs []pia.Message) {
	hdr := pia.Header{Connection: 1, SrcTimer: uint16(time.Since(h.start).Milliseconds()), DstTimer: theirTimer}
	if c, ok := h.conn1[to.String()]; ok {
		h.pkt[to.String()]++
		if h.pkt[to.String()] == 0 {
			h.pkt[to.String()] = 1
		}
		hdr.Connection, hdr.PacketID = c, h.pkt[to.String()]
	}
	raw, err := pia.Encode(hdr, msgs, h.key)
	if err != nil {
		log.Printf("host leg: encode: %v", err)
		return
	}
	if _, err := h.conn.WriteTo(raw, to); err != nil {
		log.Printf("host leg: send: %v", err)
	}
	h.stats.PacketsOut++
	if h.capture != nil {
		h.capture(raw, to.String(), true)
	}
}

func (h *hostLeg) handle(b []byte, from net.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stats.PacketsIn++
	p, err := pia.Decode(b, h.key)
	if err != nil {
		return
	}
	peer := from.String()
	if p.Connection > 1 {
		h.conn1[peer] = p.Connection
	}
	for _, m := range p.Messages {
		// connected-station message: we are station 0 (host), the joiner station 1 (destination bitmap 0x2)
		reply := func(proto uint16, port uint16, payload []byte) {
			h.sendMsgs(from, p.SrcTimer, []pia.Message{{SrcStation: 0, Destination: 0x2, SrcConstant: 1, Protocol: proto, Port: port, Payload: payload}})
		}
		switch m.Protocol {
		case pia.ProtoRTT:
			if len(m.Payload) >= 16 && m.Payload[3] == 0 {
				out := append([]byte(nil), m.Payload[:16]...)
				out[3] = 1 // response, same system time
				reply(pia.ProtoRTT, m.Port, out)
			}
			continue
		case pia.ProtoReliable:
			h.reliable(from, p.SrcTimer, m)
			continue
		case pia.ProtoUnreliable:
			log.Printf("host leg: %s unreliable %dB: %s", peer, len(m.Payload), hexHead(m.Payload, 48))
			continue
		case pia.ProtoSessionClk:
			if len(m.Payload) >= 16 {
				out := append([]byte(nil), m.Payload[:8]...)
				out = binary.BigEndian.AppendUint64(out, uint64(time.Since(h.start).Milliseconds()))
				reply(pia.ProtoSessionClk, m.Port, out)
			}
			continue
		}
		if m.Protocol == pia.ProtoSession {
			if j, ok := pia.ParseJoinRequest(m.Payload); ok {
				req := h.info[peer]
				if req == nil {
					log.Printf("host leg: %s join request before a station connection", peer)
					continue
				}
				log.Printf("host leg: %s mesh join request (ack %08x) -> join response, host 0, joiner 1", peer, j.AckID)
				h.joinAck[peer] = j.AckID
				h.sendProto(from, p.SrcTimer, pia.ProtoSession, 0, pia.JoinResponse(0, 1, []pia.MeshStation{
					{Public: h.location(3), Private: h.location(0), Index: 0},
					{Public: req.Public, Private: req.Private, Index: 1},
				}, j.AckID))
				continue
			}
		}
		if m.Protocol != pia.ProtoStation {
			log.Printf("host leg: %s %s port %d %dB (not answered)", peer, pia.ProtoName(m.Protocol), m.Port, len(m.Payload))
			continue
		}
		s, err := pia.ParseStation(m.Payload)
		if err != nil {
			log.Printf("host leg: %s station: %v", peer, err)
			continue
		}
		switch {
		case s.Request != nil && !s.Request.Inverse:
			ack := pia.AckMessage(s.Request.AckID)
			if _, sent := h.ours[peer]; sent {
				h.send(from, p.SrcTimer, ack) // a resend: ack again, the inverse request is already out
				continue
			}
			inv := pia.ConnRequest{ConnID: s.Request.ConnID, Version: s.Request.Version, Inverse: true,
				Public: h.location(3), Private: h.location(0), AckID: rnd32()}
			h.ours[peer] = inv.AckID
			h.info[peer] = s.Request
			log.Printf("host leg: %s connection request (conn %d, station version %d, PID %d) -> ack + inverse request", peer,
				s.Request.ConnID, s.Request.Version, s.Request.Public.PID)
			h.send(from, p.SrcTimer, ack, inv.Marshal())
		case s.Type == pia.StationAck:
			log.Printf("host leg: %s ack %08x (ours %08x)", peer, s.AckID, h.ours[peer])
			if h.joinAck[peer] != 0 && s.AckID == h.joinAck[peer] && h.rel[peer] == nil {
				// the joiner holds our join response: the game host greets it with PlayerId (type 0, slot 1)
				h.rel[peer] = &relState{sendSeq: pia.ReliableFirstSeq, recvNext: pia.ReliableFirstSeq, pending: map[uint32][]byte{}}
				// a real host follows the join with an update-mesh carrying every StationInfo; the joiner registers the stations
				// (and resolves their PIDs) from it
				if req := h.info[peer]; req != nil {
					h.sendProto(from, p.SrcTimer, pia.ProtoSession, 0, pia.UpdateMesh(0, 1, []pia.MeshStation{
						{Public: h.location(3), Private: h.location(0), Index: 0},
						{Public: req.Public, Private: req.Private, Index: 1},
					}))
					log.Printf("host leg: %s update mesh (2 stations)", peer)
				}
				// The client creates the host's gamer on its next session sync, a moment after the mesh join; a PlayerId that
				// arrives earlier is acked by PIA and dropped by the game. Greet after a short delay and repeat until Hello.
				st := h.rel[peer]
				go func() {
					if !h.Greet {
						return
					}
					for i := 0; i < 6 && !st.hello; i++ {
						time.Sleep(2 * time.Second)
						h.mu.Lock()
						if !st.hello {
							log.Printf("host leg: %s Terraria PlayerId slot 1 (try %d)", peer, i+1)
							h.sendGame(from, 0, []byte{0x00, 0x01})
						}
						h.mu.Unlock()
					}
				}()
			}
		case s.Response != nil:
			log.Printf("host leg: %s connection response result %d version %d platform %d token %q player %q", peer,
				s.Response.Result, s.Response.Version, s.Response.Platform, s.Response.Token, s.Response.Player.Name)
			msgs := [][]byte{pia.AckMessage(s.Response.AckID)}
			if !h.done[peer] && s.Response.Result == 0 {
				h.done[peer] = true
				msgs = append(msgs, pia.ConnResponse{Version: s.Response.Version, Platform: pia.PlatformWiiU,
					Token: s.Response.Token, Player: pia.PlayerInfo{Name: "OpenPak relay", Language: s.Response.Player.Language},
					AckID: rnd32()}.Marshal())
			}
			h.send(from, p.SrcTimer, msgs...)
		default:
			log.Printf("host leg: %s station type %d", peer, s.Type)
		}
	}
}

// sendGame sends one Terraria message to the joiner over the reliable channel (port 1).
func (h *hostLeg) sendGame(to net.Addr, theirTimer uint16, payload []byte) {
	st := h.rel[to.String()]
	m := pia.ReliableMsg{Flags: pia.RelData | pia.RelLast, Seq: st.sendSeq, Ack: st.recvNext, Payload: payload}
	st.pending[st.sendSeq] = m.Marshal()
	st.sendSeq++
	h.sendMsgs(to, theirTimer, []pia.Message{{SrcStation: 0, Destination: 0x2, SrcConstant: 1, Protocol: pia.ProtoReliable, Port: pia.ReliablePort, Payload: m.Marshal()}})
}

// reliable handles the joiner's reliable stream: acks, Terraria messages (logged and answered as a host would).
func (h *hostLeg) reliable(from net.Addr, theirTimer uint16, m pia.Message) {
	peer := from.String()
	st := h.rel[peer]
	r, err := pia.ParseReliable(m.Payload)
	if err != nil || st == nil {
		log.Printf("host leg: %s reliable (port %d) unparsed %dB: %s", peer, m.Port, len(m.Payload), hexHead(m.Payload, 48))
		return
	}
	for seq := range st.pending {
		if int32(seq-r.Ack) < 0 {
			delete(st.pending, seq)
		}
	}
	if !r.IsData() {
		return
	}
	if r.Seq == st.recvNext {
		st.recvNext++
		h.stats.GameIn++
		log.Printf("host leg: %s terraria msg type %d (%d bytes)", peer, r.Payload[0], len(r.Payload))
		if h.OnGame != nil {
			h.OnGame(peer, r.Payload)
		}
		if r.Payload[0] == 0x01 {
			st.hello = true
			if h.Greet && len(r.Payload) >= 3 {
				// Hello [01][version][slot]: request player info [03][slot], as the host does for a matching version
				log.Printf("host leg: %s Hello, version %d, slot %d -> request player info", peer, r.Payload[1], r.Payload[2])
				h.sendGame(from, theirTimer, []byte{0x03, r.Payload[2]})
			}
		}
	}
	ack := pia.ReliableMsg{Ack: st.recvNext}
	h.sendMsgs(from, theirTimer, []pia.Message{{SrcStation: 0, Destination: 0x2, SrcConstant: 1, Protocol: pia.ProtoReliable, Port: m.Port, Payload: ack.Marshal()}})
}

func hexHead(b []byte, n int) string {
	if len(b) > n {
		return hex.EncodeToString(b[:n]) + "..."
	}
	return hex.EncodeToString(b)
}
