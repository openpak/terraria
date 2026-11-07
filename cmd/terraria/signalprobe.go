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
		HostJID: host + "@" + domain + "/ps3",
		SelfJID: cl.JID,
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
	p.Send = func(s string) error {
		log.Printf("signalprobe: >> %s", s)
		return cl.Send(s)
	}
	cl.Log = func(s string) { log.Printf("signalprobe: << %s", s) }
	probed := false
	var rc *rudp.Conn
	p.OnProbe = func(c rtsig.Candidate) {
		log.Printf("signalprobe: host candidate %s:%d, probing", c.Address, c.Port)
		// Send our own type-1 probes to every host candidate: the host expects a probe from us
		// before it answers (observed: it terminates after ~10s when none arrive).
		go func() {
			pkt := p.ProbePacketFor()
			for i := 0; i < 40; i++ {
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
			if err := rc.Send([]byte{1, 1, 1}); err != nil { // joiner Hello [01][01][slot=1] [I]
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
			if len(pkt) == 0x58 && pkt[0] <= 3 {
				log.Printf("signalprobe: probe %d bytes from %s type=%d %x", n, src, pkt[0], pkt)
				if resp := p.ProbeResponseFor(pkt); resp != nil {
					udp.WriteToUDP(resp, src)
				}
				if !probed && !src.IP.IsLoopback() {
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
			if rc != nil {
				if err := rc.HandleDatagram(pkt); err != nil {
					log.Printf("signalprobe: rudp: %v", err)
				}
			}
		}
	}()
	if err := p.Start(); err != nil {
		return err
	}
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
