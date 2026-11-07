package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/openpak/terraria/internal/pia"
)

// A simulated Wii U client (the sequence Terraria in Quay sends, prds#145) against the relay in greet mode: station handshake,
// mesh join, then the Terraria greeting: PlayerId from the host, Hello from the client, request-player-info from the host.
func TestWiiUClientReachesTerrariaGreeting(t *testing.T) {
	srv, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer srv.Close()
	public := netip.MustParseAddrPort(srv.LocalAddr().String())
	key := bytes.Repeat([]byte{7}, 32)
	rl := &Relay{Conn: srv, Public: public, Greet: true}
	if _, err := rl.Register(context.Background(), LegSpec{CoreSession: "s", Gathering: 9, HostPID: 4242, SessionKey: hex.EncodeToString(key)}); err != nil {
		t.Fatal(err)
	}
	go rl.Serve(context.Background())

	cl, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer cl.Close()
	me := netip.MustParseAddrPort(cl.LocalAddr().String())
	loc := pia.StationLocation{Addr: me, PID: 1570020176, RVCID: 3, URLType: 1, SID: 15, NATMapping: 1, NATFilter: 2, NATType: 3}
	send := func(conn uint8, msgs ...pia.Message) {
		raw, _ := pia.Encode(pia.Header{Connection: conn}, msgs, key)
		cl.WriteTo(raw, srv.LocalAddr())
	}
	recv := func() []pia.Message {
		buf := make([]byte, 2048)
		cl.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := cl.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no answer: %v", err)
		}
		p, err := pia.Decode(buf[:n], key)
		if err != nil {
			t.Fatal(err)
		}
		return p.Messages
	}
	st := func(payload []byte) pia.Message { return pia.Message{SrcStation: 0xfd, Protocol: pia.ProtoStation, Payload: payload} }

	send(1, st(pia.ConnRequest{ConnID: 40, Version: 3, Public: loc, Private: loc, AckID: 11}.Marshal()))
	m := recv() // ack + inverse request
	if len(m) != 2 {
		t.Fatalf("want ack + inverse, got %d", len(m))
	}
	inv, _ := pia.ParseStation(m[1].Payload)
	if inv.Request == nil || !inv.Request.Inverse || inv.Request.Public.PID != 4242 {
		t.Fatalf("inverse %+v", inv)
	}
	send(1, st(pia.AckMessage(inv.Request.AckID)), st(pia.ConnResponse{Version: 3, Platform: 3, Player: pia.PlayerInfo{Name: "Wii"}, AckID: 12}.Marshal()))
	m = recv() // ack + our response
	resp, _ := pia.ParseStation(m[len(m)-1].Payload)
	if resp.Response == nil || resp.Response.Result != 0 {
		t.Fatalf("response %+v", resp)
	}
	send(1, st(pia.AckMessage(resp.Response.AckID)), pia.Message{SrcStation: 0xfd, Protocol: pia.ProtoSession, Payload: pia.JoinRequestMessage(loc, 13)})
	m = recv() // join response
	if m[0].Protocol != pia.ProtoSession || m[0].Payload[0] != pia.MeshJoinResp || m[0].Payload[2] != 0 || m[0].Payload[3] != 1 {
		t.Fatalf("join response %x", m[0].Payload)
	}
	send(41, st(pia.AckMessage(13)))
	m = recv() // update mesh
	if m[0].Protocol != pia.ProtoSession || m[0].Payload[0] != pia.MeshUpdate {
		t.Fatalf("want update mesh, got %x", m[0].Payload)
	}
	m = recv() // PlayerId over reliable port 1
	r, err := pia.ParseReliable(m[0].Payload)
	if err != nil || m[0].Protocol != pia.ProtoReliable || m[0].Port != pia.ReliablePort || !bytes.Equal(r.Payload, []byte{0, 1}) || r.Seq != pia.ReliableFirstSeq {
		t.Fatalf("PlayerId %v %+v", err, r)
	}
	hello := pia.ReliableMsg{Flags: 3, Seq: pia.ReliableFirstSeq, Ack: r.Seq + 1, Payload: []byte{1, 13, 1}}
	send(41, pia.Message{SrcStation: 1, Destination: 1, SrcConstant: 3, Protocol: pia.ProtoReliable, Port: 1, Payload: hello.Marshal()})
	for i := 0; i < 4; i++ {
		for _, x := range recv() {
			if x.Protocol != pia.ProtoReliable {
				continue
			}
			if rr, _ := pia.ParseReliable(x.Payload); rr.IsData() && bytes.Equal(rr.Payload, []byte{3, 1}) {
				if got := rl.Legs()[0]["game_in"].(int64); got != 1 {
					t.Fatalf("game_in %d", got)
				}
				return
			}
		}
	}
	t.Fatal("no request-player-info after Hello")
}

func TestUnknownKeyIsIgnored(t *testing.T) {
	srv, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer srv.Close()
	rl := &Relay{Conn: srv, Public: netip.MustParseAddrPort(srv.LocalAddr().String())}
	rl.Register(context.Background(), LegSpec{CoreSession: "s", HostPID: 1, SessionKey: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))})
	raw, _ := pia.Encode(pia.Header{Connection: 1}, []pia.Message{{Protocol: pia.ProtoStation, Payload: []byte{5, 0, 0, 0, 0, 0, 0, 1}}}, bytes.Repeat([]byte{2}, 32))
	if l := rl.legFor(raw, "x:1"); l != nil {
		t.Fatal("a packet signed with another key must not match a leg")
	}
	if _, err := rl.Register(context.Background(), LegSpec{SessionKey: "zz"}); err == nil {
		t.Fatal("bad key accepted")
	}
}
