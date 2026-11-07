// Package relay carries Terraria between consoles of the same compat group (prds#145). Leg W ("wiiu") stands in for a host on
// another network: a Wii U joining a shadow gathering is pointed here by the nex Terraria title, which registers the leg first
// (session key, host PID). The relay finds the leg of a new peer by the packet signature (HMAC-MD5 with that leg's key).
package relay

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/openpak/terraria/internal/pia"
	"github.com/openpak/terraria/internal/store"
)

// LegSpec registers a leg: a Wii U will join core session CoreSession (gathering Gathering) and believe the relay is host HostPID.
type LegSpec struct {
	CoreSession string `json:"core_session"`
	Gathering   int64  `json:"gathering"`
	HostPID     uint32 `json:"host_pid"`
	JoinerPID   uint32 `json:"joiner_pid"`
	SessionKey  string `json:"session_key"` // hex, never logged or stored
}

type leg struct {
	id    int64
	spec  LegSpec
	key   []byte
	host  *hostLeg
	added time.Time
	peers map[string]bool
}

// Relay owns the UDP socket of the Wii U leg.
type Relay struct {
	Conn   net.PacketConn
	Public netip.AddrPort // the address consoles are given
	Store  *store.Store
	// Greet: legs act as the Terraria host themselves (test mode until the PS3 leg forwards a real host).
	Greet bool
	// LegTTL: an unconnected leg is dropped after this long.
	LegTTL time.Duration

	mu    sync.Mutex
	legs  map[int64]*leg
	peers map[string]*leg
}

// Register adds a leg and returns its id.
func (r *Relay) Register(ctx context.Context, s LegSpec) (int64, error) {
	key, err := hex.DecodeString(s.SessionKey)
	if err != nil || len(key) < 16 {
		return 0, fmt.Errorf("session_key: want hex of at least 16 bytes")
	}
	id := int64(0)
	if r.Store != nil {
		if id, err = r.Store.CreateLeg(ctx, store.Leg{Network: "wiiu", CoreSession: s.CoreSession, Gathering: s.Gathering,
			HostPID: int64(s.HostPID), JoinerPID: int64(s.JoinerPID)}); err != nil {
			return 0, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.legs == nil {
		r.legs, r.peers = map[int64]*leg{}, map[string]*leg{}
	}
	if id == 0 {
		id = int64(len(r.legs) + 1)
	}
	l := &leg{id: id, spec: s, key: key, added: time.Now(), peers: map[string]bool{}}
	l.host = newHostLeg(r.Conn, key, s.HostPID, r.Public, nil)
	l.host.Greet = r.Greet
	l.host.OnGame = func(peer string, msg []byte) {} // the PS3 leg plugs in here
	r.legs[id] = l
	log.Printf("relay: leg %d registered: core session %s, gathering %d, host PID %d", id, s.CoreSession, s.Gathering, s.HostPID)
	return id, nil
}

// Legs lists the registered legs (no keys).
func (r *Relay) Legs() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, l := range r.legs {
		st := l.host.stats
		out = append(out, map[string]any{"id": l.id, "core_session": l.spec.CoreSession, "gathering": l.spec.Gathering,
			"host_pid": l.spec.HostPID, "peers": len(l.peers), "packets_in": st.PacketsIn, "packets_out": st.PacketsOut, "game_in": st.GameIn})
	}
	return out
}

// Serve reads the socket until it closes.
func (r *Relay) Serve(ctx context.Context) error {
	go r.housekeeping(ctx)
	buf := make([]byte, 2048)
	for {
		n, from, err := r.Conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		b := append([]byte(nil), buf[:n]...)
		if !pia.IsPIA(b) {
			continue
		}
		l := r.legFor(b, from.String())
		if l == nil {
			continue
		}
		l.host.handle(b, from)
	}
}

// legFor returns the peer's leg, matching a new peer by signature against the legs that have no peer yet.
func (r *Relay) legFor(b []byte, peer string) *leg {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l := r.peers[peer]; l != nil {
		return l
	}
	for _, l := range r.legs {
		if _, err := pia.Decode(b, l.key); err == nil {
			r.peers[peer] = l
			l.peers[peer] = true
			log.Printf("relay: leg %d: console %s connected", l.id, peer)
			if r.Store != nil {
				go r.Store.Connected(context.Background(), l.id, peer)
			}
			return l
		}
	}
	return nil
}

// housekeeping persists counters and drops legs that never connected.
func (r *Relay) housekeeping(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ttl := r.LegTTL
		if ttl == 0 {
			ttl = 2 * time.Minute
		}
		r.mu.Lock()
		for id, l := range r.legs {
			st := l.host.stats
			if r.Store != nil {
				r.Store.Counters(ctx, id, st.PacketsIn, st.PacketsOut, st.GameIn)
			}
			if len(l.peers) == 0 && time.Since(l.added) > ttl {
				delete(r.legs, id)
				if r.Store != nil {
					r.Store.End(ctx, id, "never connected")
				}
				log.Printf("relay: leg %d dropped, never connected", id)
			}
		}
		r.mu.Unlock()
	}
}
