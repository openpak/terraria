package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openpak/terraria/internal/pia"
)

// join runs the client side of the PIA handshake against a Wii U host (relay leg W towards a Wii U host, prds#145): station
// connection, mesh join, then it answers RTT/clock and records everything the host sends.
func join(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	to := fs.String("to", "", "host PIA address ip:port")
	listen := fs.String("listen", ":49201", "local UDP address")
	self := fs.String("self", "", "our address as the host reaches it (ip:port)")
	keyFile := fs.String("key", "", "session key file (hex)")
	pid := fs.Uint("pid", 0, "our PID (a participant of the host's gathering)")
	out := fs.String("out", "join.jsonl", "capture file")
	dur := fs.Duration("for", 60*time.Second, "how long to stay")
	fs.Parse(args)
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	// -to auto: wait for the host's first packet (its NAT probe after InitiateProbe) and use its source address.
	var host net.Addr
	if *to != "auto" {
		if host, err = net.ResolveUDPAddr("udp4", *to); err != nil {
			return err
		}
	}
	me, err := netip.ParseAddrPort(*self)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		return err
	}
	start := time.Now()
	loc := func(t uint8) pia.StationLocation {
		return pia.StationLocation{Addr: me, PID: uint32(*pid), RVCID: 1, URLType: 1, SID: 0x0f, NATMapping: 1, NATFilter: 2, NATType: t}
	}
	var connID uint8
	var pkt uint16
	connected := false
	send := func(src uint8, dst, srcConst uint32, proto uint16, port uint16, theirTimer uint16, payloads ...[]byte) {
		var msgs []pia.Message
		for _, p := range payloads {
			msgs = append(msgs, pia.Message{SrcStation: src, Destination: dst, SrcConstant: srcConst, Protocol: proto, Port: port, Payload: p})
		}
		h := pia.Header{Connection: 1, SrcTimer: uint16(time.Since(start).Milliseconds()), DstTimer: theirTimer}
		if connected && connID > 1 {
			pkt++
			h.Connection, h.PacketID = connID, pkt
		}
		raw, err := pia.Encode(h, msgs, key)
		if err != nil {
			log.Printf("encode: %v", err)
			return
		}
		conn.WriteTo(raw, host)
		r := capture(raw, key)
		r.From, r.Dir = host.String(), "out"
		enc.Encode(r)
	}
	if host == nil {
		log.Printf("join: waiting for the host's first packet on %s", conn.LocalAddr())
		conn.SetReadDeadline(time.Now().Add(*dur))
		n, from, err := conn.ReadFrom(make([]byte, 2048))
		if err != nil {
			return fmt.Errorf("no packet from the host: %w", err)
		}
		host = from
		log.Printf("join: host is %s (%d bytes first)", host, n)
	}
	req := pia.ConnRequest{ConnID: uint8(rnd32()%250) + 2, Version: pia.StationVersion3, Public: loc(3), Private: loc(0), AckID: rnd32()}
	connID = req.ConnID
	probe := make([]byte, 16)
	binary.BigEndian.PutUint32(probe, 1)
	binary.BigEndian.PutUint64(probe[8:], uint64(time.Now().UnixNano()))
	send(0xfd, 0, 0, pia.ProtoNAT, 1, 0, probe)
	send(0xfd, 0, 0, pia.ProtoStation, 0, 0, req.Marshal())
	log.Printf("join: NAT probe + connection request to %s (conn %d)", host, req.ConnID)
	joinAck := rnd32()
	myIndex := uint8(0xfd)
	deadline := time.Now().Add(*dur)
	buf := make([]byte, 2048)
	resend := time.Now()
	stage := "connreq"
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if time.Since(resend) > 500*time.Millisecond {
				resend = time.Now()
				switch stage {
				case "connreq":
					send(0xfd, 0, 0, pia.ProtoStation, 0, 0, req.Marshal())
				case "join":
					send(0xfd, 0, 0, pia.ProtoSession, 0, 0, pia.JoinRequestMessage(loc(3), joinAck))
				}
			}
			continue
		}
		r := capture(buf[:n], key)
		r.From, r.Dir = from.String(), "in"
		enc.Encode(r)
		p, err := pia.Decode(buf[:n], key)
		if err != nil {
			log.Printf("in: %v", err)
			continue
		}
		for _, m := range p.Messages {
			switch m.Protocol {
			case pia.ProtoStation:
				s, err := pia.ParseStation(m.Payload)
				if err != nil {
					log.Printf("station: %v", err)
					continue
				}
				switch {
				case s.Type == pia.StationAck:
					log.Printf("join: host acked %08x", s.AckID)
				case s.Request != nil && s.Request.Inverse:
					log.Printf("join: inverse request (conn %d, PID %d) -> ack + our response", s.Request.ConnID, s.Request.Public.PID)
					send(0xfd, 0, 0, pia.ProtoStation, 0, p.SrcTimer, pia.AckMessage(s.Request.AckID),
						pia.ConnResponse{Version: pia.StationVersion3, Platform: pia.PlatformWiiU, Player: pia.PlayerInfo{Name: "OpenPak relay", Language: 1}, AckID: rnd32()}.Marshal())
					stage = "resp"
				case s.Response != nil:
					log.Printf("join: host response result %d player %q -> ack, mesh join", s.Response.Result, s.Response.Player.Name)
					send(0xfd, 0, 0, pia.ProtoStation, 0, p.SrcTimer, pia.AckMessage(s.Response.AckID))
					stage = "join"
					send(0xfd, 0, 0, pia.ProtoSession, 0, p.SrcTimer, pia.JoinRequestMessage(loc(3), joinAck))
				}
			case pia.ProtoSession:
				if len(m.Payload) >= 4 && m.Payload[0] == pia.MeshJoinResp {
					myIndex = m.Payload[3]
					ack := binary.BigEndian.Uint32(m.Payload[len(m.Payload)-4:])
					log.Printf("join: join response, %d stations, host %d, me %d -> ack", m.Payload[1], m.Payload[2], myIndex)
					send(0xfd, 0, 0, pia.ProtoStation, 0, p.SrcTimer, pia.AckMessage(ack))
					stage, connected = "in", true
					if p.Connection > 1 {
						connID = p.Connection
					}
				} else {
					log.Printf("join: session message type %d (%d bytes)", m.Payload[0], len(m.Payload))
				}
			case pia.ProtoRTT:
				if len(m.Payload) >= 16 && m.Payload[3] == 0 {
					o := append([]byte(nil), m.Payload[:16]...)
					o[3] = 1
					send(myIndex, 1, 1, pia.ProtoRTT, m.Port, p.SrcTimer, o)
				}
			case pia.ProtoNAT:
				// PIA 3.x NAT traversal: port 1 probe request, port 2 reply (NatProbeData: RVCID, type, padding, system time)
				log.Printf("join: NAT port %d from host: %s", m.Port, hexHead(m.Payload, 32))
				if m.Port == 1 && len(m.Payload) >= 16 {
					o := append([]byte(nil), m.Payload[:16]...)
					o[4] = 1
					send(0xfd, 0, 0, pia.ProtoNAT, 2, p.SrcTimer, o)
				}
			case pia.ProtoKeepAlive, pia.ProtoSessionClk:
			default:
				log.Printf("join: %s port %d from station %d: %d bytes %s", pia.ProtoName(m.Protocol), m.Port, m.SrcStation, len(m.Payload), hexHead(m.Payload, 48))
			}
		}
		if connected && p.Connection > 1 {
			connID = p.Connection
		}
	}
	return nil
}

func hexHead(b []byte, n int) string {
	if len(b) > n {
		return hex.EncodeToString(b[:n]) + "..."
	}
	return hex.EncodeToString(b)
}

func rnd32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
