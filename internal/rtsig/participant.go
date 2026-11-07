package rtsig

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// Participant is the relay side of the udpp2p activation with one host (spec §7 of the decode).
// It is driven by parsed stanzas from the host and by ProbeOK once the UDP probe phase has seen a
// valid peer probe; every stanza it wants sent goes through Send. Mutual is set when both activated
// stanzas have been exchanged; OnMutual (if set) fires once at that moment.
type Participant struct {
	Self     Candidate // the relay endpoint offered to the host (also the RUDP listen endpoint)

	// OfferCandidates, if non-empty, is the candidate list sent in the offer instead of just Self.
	// Mirror the host: offer stun (public mapped), static and local forms so its candidate selection
	// finds a pair it will probe.
	OfferCandidates []Candidate
	SID      uint16
	SKey     []byte // 16 bytes, stable for the session
	HostJID  string
	SelfJID  string
	Send     func(string) error
	OnMutual func(host Candidate)
	OnProbe  func(host Candidate) // probing should start toward this candidate

	peerSID   uint16
	peerKey   []byte
	hostCand  Candidate
	hostCands []Candidate
	offerOut bool // own offer sent
	offAck   bool // host acked own offer
	peerOff  bool // host offer received
	accOut   bool
	accAck   bool
	peerAcc  bool
	actOut   bool
	actIn    bool
	Mutual   bool
	seq      int
}

func (p *Participant) nextID() string { p.seq++; return "sig" + strconv.Itoa(p.seq) }

func (p *Participant) send(s string) error {
	if p.Send == nil {
		return fmt.Errorf("rtsig: no transport")
	}
	return p.Send(s)
}

// Start sends the relay's offer (step 3; also correct before the host's offer arrives).
func (p *Participant) Start() error {
	if p.offerOut {
		return nil
	}
	p.offerOut = true
	cs := p.OfferCandidates
	if len(cs) == 0 {
		cs = []Candidate{p.Self}
	}
	return p.send(Offer(p.nextID(), p.HostJID, p.SelfJID, p.SID, p.peerSID, p.SKey, 1, cs))
}

// ProbeOK reports the UDP probe phase succeeded; the accept can go out.
func (p *Participant) ProbeOK() error {
	if p.accOut || !p.peerOff {
		return nil
	}
	p.accOut = true
	c := p.Self
	c.MAddress, c.MPort = c.Address, c.Port
	return p.send(Accept(p.nextID(), p.HostJID, p.SelfJID, p.SID, p.peerSID, p.SKey, []Candidate{c}))
}

// ProbePacketFor builds the type-1 probe to send to the host (spec §7): it carries our skey,
// the host's skey, our sid and the host's sid.
func (p *Participant) ProbePacketFor() []byte {
	return ProbePacket(p.SKey, p.peerKey, p.SID, p.peerSID)
}

// ProbeResponseFor builds the type-2 answer to a host probe from this connection's fields.
func (p *Participant) ProbeResponseFor(req []byte) []byte {
	return ProbeResponsePacket(req, p.SKey, p.peerKey, p.SID, p.peerSID)
}

// ProbeVariants returns the probe packet in every plausible field order (live validator search):
// skey order × sid order, plus one carrying a current timestamp at +0x48 like the builder writes.
func (p *Participant) ProbeVariants() [][]byte {
	base := ProbePacket(p.SKey, p.peerKey, p.SID, p.peerSID)
	swapKeys := ProbePacket(p.peerKey, p.SKey, p.SID, p.peerSID)
	swapSIDs := ProbePacket(p.SKey, p.peerKey, p.peerSID, p.SID)
	swapBoth := ProbePacket(p.peerKey, p.SKey, p.peerSID, p.SID)
	stamped := append([]byte(nil), base...)
	now := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint32(stamped[0x48:], uint32(now>>32))
	binary.BigEndian.PutUint32(stamped[0x4c:], uint32(now))
	return [][]byte{base, swapKeys, swapSIDs, swapBoth, stamped}
}

// ProbeTargets returns every candidate the host offered.
func (p *Participant) ProbeTargets() []Candidate { return p.hostCands }

func (p *Participant) maybeActivated() error {
	if p.actOut || !p.accOut || !p.accAck || !p.peerAcc {
		return nil
	}
	p.actOut = true
	return p.send(Simple("activated", p.nextID(), p.HostJID, p.SelfJID, p.SID, p.peerSID))
}

func (p *Participant) checkMutual() {
	if p.Mutual || !p.actOut || !p.actIn {
		return
	}
	p.Mutual = true
	if p.OnMutual != nil {
		p.OnMutual(p.hostCand)
	}
}

// Handle consumes one parsed stanza from the host and drives the exchange.
func (p *Participant) Handle(st Stanza) error {
	// A bare result (no query) acks one of our sets: offer first, then accept.
	if st.Kind == "result" && st.Action == "" && st.NS == "" {
		if p.offerOut && !p.offAck {
			p.offAck = true
			return nil
		}
		if p.accOut && !p.accAck {
			p.accAck = true
			if err := p.maybeActivated(); err != nil {
				return err
			}
			p.checkMutual()
		}
		return nil
	}
	if st.NS == NSNetinfo {
		if st.Kind == "get" {
			return p.send(NetinfoResult(st.ID, p.HostJID, p.SelfJID, p.Self.Address, p.Self.Address, "unknown", "open", p.Self.Port, "type1"))
		}
		return nil
	}
	if st.NS != NSUdpp2p {
		return nil
	}
	switch st.Action {
	case "offer":
		p.peerSID, p.peerKey, p.peerOff = st.SID, st.SKey, true
		p.hostCands = st.Candidates
		if len(st.Candidates) > 0 {
			p.hostCand = st.Candidates[0]
			for _, c := range st.Candidates {
				if c.Type == "stun" {
					p.hostCand = c
				}
			}
		}
		if err := p.send(Ack(st.ID, p.HostJID, p.SelfJID)); err != nil {
			return err
		}
		if err := p.Start(); err != nil {
			return err
		}
		if p.OnProbe != nil {
			p.OnProbe(p.hostCand)
		}
		return nil
	case "accept":
		if st.PSID != p.SID {
			return fmt.Errorf("rtsig: accept psid %d, want own sid %d", st.PSID, p.SID)
		}
		p.peerAcc = true
		if len(st.Candidates) > 0 {
			c := st.Candidates[0]
			if c.MAddress != "" {
				c.Address, c.Port = c.MAddress, c.MPort
			}
			p.hostCand = c
		}
		if err := p.send(Ack(st.ID, p.HostJID, p.SelfJID)); err != nil {
			return err
		}
		return p.maybeActivated()
	case "activated":
		p.actIn = true
		if err := p.send(Ack(st.ID, p.HostJID, p.SelfJID)); err != nil {
			return err
		}
		p.checkMutual()
		return nil
	case "terminate", "fterminate":
		return p.send(Ack(st.ID, p.HostJID, p.SelfJID))
	}
	return nil
}
