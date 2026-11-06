package pia

import (
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestParseRealConnectionRequest(t *testing.T) {
	raw, _ := hex.DecodeString(strings.TrimSpace(string(must(os.ReadFile("testdata/quay-connreq.hex")))))
	p, _ := Decode(raw[:len(raw)-SigLen], nil)
	m, err := ParseStation(p.Messages[0].Payload)
	if err != nil || m.Request == nil {
		t.Fatal(err)
	}
	r := m.Request
	if r.Version != StationVersion3 || r.Inverse || r.Public.PID != r.Private.PID || r.Public.SID != 0x0f || r.Public.NATType != 3 {
		t.Fatalf("%+v", r)
	}
	if string(r.Marshal()) != string(p.Messages[0].Payload) {
		t.Fatal("marshal does not reproduce the console's bytes")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	in := ConnResponse{Version: 3, Platform: PlatformWiiU, Token: "abc", Player: PlayerInfo{Name: "Relay", Language: 1}, AckID: 9}
	m, err := ParseStation(in.Marshal())
	if err != nil || m.Response == nil || m.Response.Token != "abc" || m.Response.Player.Name != "Relay" || m.Response.AckID != 9 {
		t.Fatalf("%v %+v", err, m.Response)
	}
	req := ConnRequest{ConnID: 7, Version: 3, Inverse: true, Public: StationLocation{Addr: netip.MustParseAddrPort("10.0.0.1:49200"), PID: 5}, AckID: 3}
	m, _ = ParseStation(req.Marshal())
	if !m.Request.Inverse || m.Request.Public.Addr.Port() != 49200 || m.Request.AckID != 3 {
		t.Fatalf("%+v", m.Request)
	}
	if a, _ := ParseStation(AckMessage(77)); a.AckID != 77 {
		t.Fatal("ack")
	}
}
