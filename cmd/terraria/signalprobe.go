package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/openpak/terraria/internal/rtsig"
	"github.com/openpak/terraria/internal/rudp"
	"github.com/openpak/terraria/internal/terra"
)

// signalprobe is the first live instrument for the PS3 relay leg: it signs into the RT stream as the
// joiner account, activates signaling toward the hosting PS3, answers its UDP probes, and logs every
// stanza and packet until mutual activation (then the host's RUDP packets arrive on the same socket).
// Config (env): RT addr/domain/ticket file, host online id, public candidate IP.
func signalprobe() error {
	addr := envOr("TERRARIA_SIGNAL_RT", "127.0.0.1:8523")
	domain := envOr("TERRARIA_SIGNAL_DOMAIN", "us.us.np.playstation.net")
	host := os.Getenv("TERRARIA_SIGNAL_HOST")
	pub := os.Getenv("TERRARIA_SIGNAL_PUBLIC_IP")
	ticketFile := os.Getenv("TERRARIA_SIGNAL_TICKET_FILE")
	if host == "" || pub == "" || ticketFile == "" {
		return fmt.Errorf("signalprobe needs TERRARIA_SIGNAL_HOST, TERRARIA_SIGNAL_PUBLIC_IP, TERRARIA_SIGNAL_TICKET_FILE")
	}
	// The ticket file is produced by `np-matching2 ticket <online id>` (the agent holds the account
	// service's signing key, as for its test clients).
	auth, err := os.ReadFile(ticketFile)
	if err != nil {
		return err
	}
	cl, err := rtsig.DialRT(addr, os.Getenv("TERRARIA_SIGNAL_TLS") == "1", domain, auth)
	if err != nil {
		return err
	}
	defer cl.Close()
	log.Printf("signalprobe: RT signed in as %s", cl.JID)
	port := 3658
	if v := os.Getenv("TERRARIA_SIGNAL_PORT"); v != "" {
		fmt.Sscan(v, &port)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return err
	}
	defer udp.Close()
	var sid uint16
	binary.Read(rand.Reader, binary.BigEndian, &sid)
	if sid == 0 {
		sid = 1
	}
	skey := make([]byte, 16)
	rand.Read(skey)
	// Offer the endpoint probes will really come from: the NAT mapping of this socket, learned via
	// STUN like a console does. The configured public address is only the fallback.
	self := rtsig.Candidate{Type: "stun", Address: pub, Port: uint16(port)}
	if stunSrv := envOr("TERRARIA_SIGNAL_STUN", "stun.l.google.com:19302"); stunSrv != "off" {
		if mapped, err := rtsig.STUNMapped(udp, stunSrv); err == nil {
			self = mapped
			log.Printf("signalprobe: stun mapped endpoint %s:%d", mapped.Address, mapped.Port)
		} else {
			log.Printf("signalprobe: stun: %v (offering configured candidate)", err)
		}
	}
	p := &rtsig.Participant{
		Self:    self,
		SID:     sid,
		SKey:    skey,
		HostJID: envOr("TERRARIA_SIGNAL_HOST_JID", host+"@"+domain+"/ps3"),
		SelfJID: cl.JID,
	}
	// An explicit host JID is the console's own NpId (run 2026-11-11 mc3: np-community stamps the stream domain on a forwarded
	// "from", which is a different NpId, and the console rejects an offer addressed to that one), so a host offer must not replace it.
	if j := os.Getenv("TERRARIA_SIGNAL_HOST_JID"); j != "" {
		if id, err := rtsig.NpIDFromJID(j); err == nil {
			p.SetHostNpID(id)
		}
	}
	// Mirror the host's offer shape: stun, static and (when known) local candidates, so the host's
	// candidate selection finds a pair it will actually probe.
	p.OfferCandidates = []rtsig.Candidate{
		self,
		{Type: "static", Address: "0.0.0.0", Port: uint16(port)},
	}
	if lip := os.Getenv("TERRARIA_SIGNAL_LOCAL_IP"); lip != "" {
		p.OfferCandidates = append(p.OfferCandidates, rtsig.Candidate{Type: "local", Address: lip, Port: uint16(port)})
	}
	if os.Getenv("TERRARIA_SIGNAL_LOCAL_ONLY") == "1" {
		// Same-subnet test: offer only the local candidate so the host pairs its local candidate
		// with ours instead of the (shared-NAT) stun endpoint.
		p.Self = rtsig.Candidate{Type: "local", Address: os.Getenv("TERRARIA_SIGNAL_LOCAL_IP"), Port: uint16(port)}
		p.OfferCandidates = []rtsig.Candidate{p.Self}
	}
	p.Send = func(s string) error {
		log.Printf("signalprobe: >> %s", s)
		return cl.Send(s)
	}
	cl.Log = func(s string) { log.Printf("signalprobe: << %s", s) }
	probed, established := false, false
	var rc *rudp.Conn
	p.OnProbe = func(c rtsig.Candidate) {
		log.Printf("signalprobe: host candidate %s:%d, probing", c.Address, c.Port)
		// Send our own type-1 probes to every host candidate. The host probes us for 10 s (vsh state 7
		// deadline) and sends terminate if no candidate got a valid type-2 back by then.
		go func() {
			body, err := p.ProbePacketFor()
			if err != nil {
				log.Printf("signalprobe: probe: %v", err)
				return
			}
			pkt := rtsig.FrameSignal(body)
			if os.Getenv("TERRARIA_SIGNAL_SPRAY") == "1" {
				// Find the host's real signaling port: spray the probe across its local address.
				for _, t := range p.ProbeTargets() {
					if t.Type != "local" {
						continue
					}
					for port := 1; port <= 65535; port++ {
						udp.WriteToUDP(pkt, &net.UDPAddr{IP: net.ParseIP(t.Address), Port: port})
					}
					log.Printf("signalprobe: sprayed probe to %s ports 1-65535", t.Address)
				}
			}
			for i := 0; i < 40; i++ {
				// Fresh send time per round: the host echoes it in its type-2 (RTT).
				if body, err := p.ProbePacketFor(); err == nil {
					pkt = rtsig.FrameSignal(body)
				}
				for _, t := range p.ProbeTargets() {
					dst := &net.UDPAddr{IP: net.ParseIP(t.Address), Port: int(t.Port)}
					if dst.IP == nil || dst.Port == 0 || dst.IP.IsUnspecified() {
						continue
					}
					if _, err := udp.WriteToUDP(pkt, dst); err != nil {
						log.Printf("signalprobe: probe to %s: %v", dst, err)
					}
				}
				time.Sleep(500 * time.Millisecond)
			}
		}()
	}
	p.OnMutual = func(c rtsig.Candidate) {
		log.Printf("signalprobe: MUTUAL ACTIVATED, host RUDP endpoint %s:%d", c.Address, c.Port)
		var isn uint16
		var cid uint32
		binary.Read(rand.Reader, binary.BigEndian, &isn)
		binary.Read(rand.Reader, binary.BigEndian, &cid)
		rc = rudp.New(udp, &net.UDPAddr{IP: net.ParseIP(c.Address), Port: int(c.Port)}, isn, cid)
		rc.OnPayload = func(b []byte) { log.Printf("signalprobe: game payload %d bytes: %x", len(b), b) }
		rc.OnEstablished = func() {
			log.Printf("signalprobe: RUDP ESTABLISHED, sending Terraria Hello")
			if err := rc.Send(terra.Hello(terra.PS3, 1)); err != nil { // version 15 on NPEB01270 v01.12 (decompile); the old 1 was the v01.00 disc build
				log.Printf("signalprobe: hello: %v", err)
			}
		}
		if err := rc.Start(); err != nil {
			log.Printf("signalprobe: rudp start: %v", err)
		}
	}
	// One socket serves the probe phase first and RUDP after mutual: probes are 0x58-byte packets with
	// first byte <= 3, RUDP frames start with a class/length word (first byte 0x40..0xff).
	go func() {
		buf := make([]byte, 4096)
		for {
			udp.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, src, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			// Every PS3 datagram carries the UDPP2P header; record kind/vports of anything that is not a
			// signaling probe (RUDP data uses its own kind/vports, card #145).
			if kind, sv, dv, body, err := rtsig.Unframe(pkt); err != nil {
				log.Printf("signalprobe: UNFRAMED %d bytes from %s: %x", n, src, pkt)
			} else if dv == rtsig.VPortSignal && len(body) > 0 && body[0] == 4 {
				log.Printf("signalprobe: HOST echo %x from %s, answered", body, src)
				if r := rtsig.EchoReply(body); r != nil {
					udp.WriteToUDP(rtsig.FrameSignal(r), src)
				}
				continue
			} else if est, ok := rtsig.Bandwidth(body); ok && dv == rtsig.VPortSignal && p.FromHost(body) {
				// Sent only from vsh state 10: the host's connection is ESTABLISHED. No reply is expected.
				if !established {
					established = true
					log.Printf("signalprobe: HOST ESTABLISHED (type-3 bandwidth pair, %d bytes, estimate of us %d)", n, est)
				}
				continue
			} else if len(body) == 0x58 && body[0] <= 2 && dv == rtsig.VPortSignal {
				if !p.FromHost(body) {
					// Our own probe hairpinned back by the shared NAT (own NpId at +0x04): never answer it
					// and never treat it as the host (2026-11-10: every "host probe" was one of these).
					log.Printf("signalprobe: own probe reflected from %s type=%d (ignored)", src, body[0])
					continue
				}
				log.Printf("signalprobe: HOST probe %d bytes from %s kind=%d vport %#x->%#x type=%d %x", n, src, kind, sv, dv, body[0], body)
				if resp := p.ProbeResponseFor(body, src); resp != nil {
					udp.WriteToUDP(rtsig.FrameSignal(resp), src)
				}
				if m := rtsig.ProbeMapped(body); m != nil {
					log.Printf("signalprobe: host sees us at %s", m)
				}
				if !probed {
					probed = true
					go func() {
						time.Sleep(200 * time.Millisecond)
						if err := p.ProbeOK(); err != nil {
							log.Printf("signalprobe: accept after probe: %v", err)
						}
					}()
				}
				continue
			}
			log.Printf("signalprobe: udp %d bytes from %s: %x", n, src, pkt)
			// ponytail: RUDP framing on the game socket (kind/vports) is unrecorded; the raw datagram is
			// handed to rudp as before until a live capture shows it.
			if rc != nil {
				if err := rc.HandleDatagram(pkt); err != nil {
					log.Printf("signalprobe: rudp: %v", err)
				}
			}
		}
	}()
	// TERRARIA_SIGNAL_WAIT_OFFER=<s>: give the host's game time to offer first (its ActivateConnection toward
	// our Matching2 member NpId, the connection its Terraria references); offer ourselves only after that.
	wait := 0
	fmt.Sscan(os.Getenv("TERRARIA_SIGNAL_WAIT_OFFER"), &wait)
	time.AfterFunc(time.Duration(wait)*time.Second, func() {
		if err := p.Start(); err != nil {
			log.Printf("signalprobe: offer: %v", err)
		}
	})
	done := time.After(10 * time.Minute)
	errc := make(chan error, 1)
	go func() { errc <- cl.Run(p) }()
	select {
	case err := <-errc:
		return err
	case <-done:
		log.Printf("signalprobe: window over, mutual=%v", p.Mutual)
		return nil
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
