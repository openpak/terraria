package rtsig

import (
	"strings"
	"testing"
)

func TestStanzaShapes(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	offer := Offer("a", "H@d/ps3", "J@d/ps3", 7, 0, key, 2, []Candidate{{Type: "stun", Address: "203.0.113.5", Port: 3658}})
	st, err := Parse(offer)
	if err != nil || st.Action != "offer" || st.SID != 7 || st.NATType != 2 || len(st.SKey) != 16 || len(st.Candidates) != 1 || st.Candidates[0].Port != 3658 {
		t.Fatalf("offer round trip: %v %+v", err, st)
	}
	if !strings.Contains(offer, `skey="000102030405060708090a0b0c0d0e0f"`) {
		t.Fatalf("skey not 32 lowercase hex: %s", offer)
	}
	acc := Accept("b", "H@d/ps3", "J@d/ps3", 7, 9, key, []Candidate{{Type: "stun", Address: "10.0.0.1", Port: 3658, MAddress: "203.0.113.5", MPort: 4000}})
	st, err = Parse(acc)
	if err != nil || st.Action != "accept" || st.PSID != 9 || st.Candidates[0].MPort != 4000 {
		t.Fatalf("accept round trip: %v %+v", err, st)
	}
	ack := Ack("a", "H@d/ps3", "J@d/ps3")
	// np-community forwards only iqs with a udpp2p/netinfo query child; a bare ack is dropped.
	if !strings.Contains(ack, `<query xmlns="`+NSUdpp2p+`"/>`) || strings.Contains(ack, "action=") {
		t.Fatalf("ack must carry an empty udpp2p query: %s", ack)
	}
	if st, err := Parse(ack); err != nil || st.Kind != "result" || st.Action != "" {
		t.Fatalf("ack round trip: %v %+v", err, st)
	}
	ni, err := Parse(NetinfoResult("c", "H@d/ps3", "J@d/ps3", "10.0.0.1", "203.0.113.5", "valid", "open", 3658, "type2"))
	if err != nil || ni.NetLocal != "10.0.0.1" || ni.NetNPPort != 3658 || ni.NetNAT != "type2" {
		t.Fatalf("netinfo round trip: %v %+v", err, ni)
	}
}

// The full exchange from the decode spec, driven from the relay side: mutual only after both
// activated stanzas, and the host endpoint for RUDP comes from its accept candidate.
func TestParticipantMutual(t *testing.T) {
	var sent []string
	mutual := false
	var mutualHost Candidate
	p := &Participant{
		Self: Candidate{Type: "stun", Address: "203.0.113.9", Port: 3658},
		SID:  7, SKey: make([]byte, 16), HostJID: "H@d/ps3", SelfJID: "J@d/ps3",
		Send:     func(s string) error { sent = append(sent, s); return nil },
		OnMutual: func(c Candidate) { mutual, mutualHost = true, c },
	}
	hostKey := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	// host offer -> ack + own offer
	if err := p.Handle(Stanza{NS: NSUdpp2p, Kind: "set", ID: "a", Action: "offer", SID: 3, SKey: hostKey, Candidates: []Candidate{{Type: "stun", Address: "198.51.100.2", Port: 3658}}}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || !strings.Contains(sent[1], `action="offer" sid="7"`) {
		t.Fatalf("after host offer: %v", sent)
	}
	// ack of own offer, then probing succeeds -> accept
	if err := p.Handle(Stanza{Kind: "result", ID: "sig1"}); err != nil {
		t.Fatal(err)
	}
	if err := p.ProbeOK(); err != nil {
		t.Fatal(err)
	}
	last := sent[len(sent)-1]
	if !strings.Contains(last, `action="accept" sid="7" psid="3"`) || !strings.Contains(last, `maddress="203.0.113.9"`) {
		t.Fatalf("accept: %s", last)
	}
	// host accept (psid must be own sid) -> ack; own accept acked -> activated; host activated -> mutual
	if err := p.Handle(Stanza{NS: NSUdpp2p, Kind: "set", ID: "c", Action: "accept", SID: 3, PSID: 7, Candidates: []Candidate{{Type: "stun", Address: "10.0.0.2", Port: 3658, MAddress: "198.51.100.2", MPort: 5000}}}); err != nil {
		t.Fatal(err)
	}
	if mutual {
		t.Fatal("mutual before activated exchange")
	}
	// activated goes out on the host accept, without the (relay-dropped) ack of our accept
	if last := sent[len(sent)-1]; !strings.Contains(last, `action="activated"`) {
		t.Fatalf("activated after host accept: %s", last)
	}
	if err := p.Handle(Stanza{NS: NSUdpp2p, Kind: "result", ID: "sig2"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Handle(Stanza{NS: NSUdpp2p, Kind: "set", ID: "e", Action: "activated", SID: 3, PSID: 7}); err != nil {
		t.Fatal(err)
	}
	if !mutual || mutualHost.Address != "198.51.100.2" || mutualHost.Port != 5000 {
		t.Fatalf("mutual host endpoint: %v %+v", mutual, mutualHost)
	}
	// a wrong psid accept is refused
	p2 := &Participant{SID: 7, Send: func(string) error { return nil }}
	if err := p2.Handle(Stanza{NS: NSUdpp2p, Kind: "set", ID: "x", Action: "accept", SID: 3, PSID: 8}); err == nil {
		t.Fatal("accept with wrong psid accepted")
	}
	// netinfo get is answered with the four groups
	var reply []string
	p3 := &Participant{Self: Candidate{Address: "203.0.113.9", Port: 3658}, HostJID: "H@d/ps3", SelfJID: "J@d/ps3", Send: func(s string) error { reply = append(reply, s); return nil }}
	if err := p3.Handle(Stanza{NS: NSNetinfo, Kind: "get", ID: "n1"}); err != nil || len(reply) != 1 || !strings.Contains(reply[0], `<nat status="type1"/>`) {
		t.Fatalf("netinfo reply: %v %v", err, reply)
	}
}
