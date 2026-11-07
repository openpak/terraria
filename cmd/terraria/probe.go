package main

import (
	"context"

	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openpak/terraria/internal/relay"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openpak/terraria/internal/pia"
)

// record is one captured datagram. Raw bytes are kept so a later decoder can re-read the capture.
type record struct {
	Time     time.Time   `json:"t"`
	From     string      `json:"from"`
	Dir      string      `json:"dir,omitempty"`
	Raw      string      `json:"raw"`
	Err      string      `json:"err,omitempty"`
	Header   *pia.Header `json:"header,omitempty"`
	Messages []msg       `json:"messages,omitempty"`
}

type msg struct {
	Proto   string `json:"proto"`
	Port    uint16 `json:"port"`
	Flags   uint8  `json:"flags"`
	Src     uint8  `json:"src_station"`
	Dst     uint32 `json:"dst"`
	SrcID   uint32 `json:"src_constant"`
	Payload string `json:"payload"`
}

func probe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	listen := fs.String("listen", ":49200", "UDP address to listen on")
	keyFile := fs.String("key", "", "file holding the NEX session key in hex (never logged)")
	out := fs.String("out", "", "capture file (JSON lines)")
	respond := fs.Bool("respond", false, "answer the station handshake as the host (relay leg W)")
	pid := fs.Uint("pid", 0, "the host PID the relay stands in for (the room owner's Wii U PID)")
	self := fs.String("self", "", "the relay's address as the console reaches it (ip:port)")
	fs.Parse(args)
	var key []byte
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		if key, err = hex.DecodeString(strings.TrimSpace(string(b))); err != nil {
			return fmt.Errorf("key file: %w", err)
		}
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		return err
	}
	log.Printf("probe listening on %s, key loaded: %t", conn.LocalAddr(), key != nil)
	enc := json.NewEncoder(w)
	if *respond {
		// host leg in test mode: one leg for the given key, acting as the Terraria host itself
		ap, err := netip.ParseAddrPort(*self)
		if err != nil {
			return fmt.Errorf("-self: %w", err)
		}
		rl := &relay.Relay{Conn: &capturingConn{PacketConn: conn, enc: enc, key: key}, Public: ap, Greet: true}
		if _, err := rl.Register(context.Background(), relay.LegSpec{CoreSession: "probe", HostPID: uint32(*pid), SessionKey: hex.EncodeToString(key)}); err != nil {
			return err
		}
		return rl.Serve(context.Background())
	}
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		r := capture(buf[:n], key)
		r.From = from.String()
		r.Dir = "in"
		enc.Encode(r)
		summary := r.Err
		for _, m := range r.Messages {
			summary += fmt.Sprintf(" [%s port %d %dB]", m.Proto, m.Port, len(m.Payload)/2)
		}
		log.Printf("%s %dB%s", from, n, summary)
	}
}

func capture(b, key []byte) record {
	r := record{Time: time.Now().UTC(), Raw: hex.EncodeToString(b)}
	if !pia.IsPIA(b) {
		r.Err = "not pia"
		return r
	}
	p, err := pia.Decode(b, key)
	if err != nil {
		r.Err = err.Error()
	}
	if p != nil {
		r.Header = &p.Header
		for _, m := range p.Messages {
			r.Messages = append(r.Messages, msg{Proto: pia.ProtoName(m.Protocol), Port: m.Port, Flags: m.Flags, Src: m.SrcStation,
				Dst: m.Destination, SrcID: m.SrcConstant, Payload: hex.EncodeToString(m.Payload)})
		}
	}
	return r
}

// capturingConn records every packet read and written (test probe only).
type capturingConn struct {
	net.PacketConn
	enc *json.Encoder
	key []byte
}

func (c *capturingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		r := capture(b[:n], c.key)
		r.From, r.Dir = from.String(), "in"
		c.enc.Encode(r)
	}
	return n, from, err
}

func (c *capturingConn) WriteTo(b []byte, to net.Addr) (int, error) {
	r := capture(b, c.key)
	r.From, r.Dir = to.String(), "out"
	c.enc.Encode(r)
	return c.PacketConn.WriteTo(b, to)
}
