package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openpak/terraria/internal/httplog"
	"github.com/openpak/terraria/internal/relay"
	"github.com/openpak/terraria/internal/store"
)

var version = "dev"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// serve runs the service: the relay's Wii U leg on UDP (TERRARIA_RELAY_ADDR, public game transport 22950) and the internal HTTP
// surface (TERRARIA_HTTP_ADDR, block 20260): /health, and /internal/legs for the console adapters (bearer TERRARIA_INTERNAL_KEY).
func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	public, err := netip.ParseAddrPort(env("TERRARIA_RELAY_PUBLIC", "127.0.0.1:22950"))
	if err != nil {
		return fmt.Errorf("TERRARIA_RELAY_PUBLIC: %w", err)
	}
	var st *store.Store
	if url := os.Getenv("TERRARIA_DATABASE_URL"); url != "" {
		if st, err = store.Open(ctx, url); err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer st.Close()
	} else {
		log.Printf("TERRARIA_DATABASE_URL unset: legs are not recorded")
	}
	conn, err := net.ListenPacket("udp4", env("TERRARIA_RELAY_ADDR", ":22950"))
	if err != nil {
		return err
	}
	rl := &relay.Relay{Conn: conn, Public: public, Store: st, Greet: os.Getenv("TERRARIA_RELAY_GREET") == "1"}
	go func() {
		if err := rl.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("relay stopped: %v", err)
			stop()
		}
	}()
	key := os.Getenv("TERRARIA_INTERNAL_KEY")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key == "" || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /internal/legs", authed(func(w http.ResponseWriter, r *http.Request) {
		var s relay.LegSpec
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&s); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		id, err := rl.Register(r.Context(), s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "relay": public.String()})
	}))
	mux.HandleFunc("GET /internal/legs", authed(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(rl.Legs())
	}))
	srv := &http.Server{Addr: env("TERRARIA_HTTP_ADDR", ":20260"), Handler: httplog.Middleware(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sh, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		srv.Shutdown(sh)
		conn.Close()
	}()
	slog.Info("terraria up", "version", version, "http", srv.Addr, "relay", conn.LocalAddr().String(), "public", public.String(), "greet", rl.Greet)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// healthcheck is the container health probe.
func healthcheck() error {
	c := http.Client{Timeout: 3 * time.Second}
	addr := env("TERRARIA_HTTP_ADDR", ":20260")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	r, err := c.Get("http://" + addr + "/health")
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("status %d", r.StatusCode)
	}
	return nil
}
