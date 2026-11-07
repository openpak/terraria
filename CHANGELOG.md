# Changelog

## v0.2.2 - 2026-11-07

`signalprobe`: the RT sign-in now speaks the RT front's PS3-era TLS (TLS 1.0–1.2, RSA-CBC suites, verification skipped for this internal participant). First live exchange: signed in as the joiner account and the hosting PS3 answered with its own udpp2p offer within a second (both forwards logged by np-community).

## v0.2.1 - 2026-11-07

PS3 relay leg, RUDP: `internal/rudp` implements the cellRudp wire protocol from the librudp decompile (aggregator frames, simultaneous SYN/SYN+ACK open, cumulative-ack data) with the decompile's first-packet bytes as a golden test, and `signalprobe` now starts RUDP toward the host candidate at mutual activation and sends the joiner Terraria Hello on ESTABLISHED, logging every game payload.

## v0.2.0 - 2026-11-07

PS3 relay leg groundwork (prds#145): `internal/rtsig` implements the NP RT signaling exchange (udpp2p/netinfo stanza codec, the offer → probe → accept → activated participant state machine, the 0x58-byte UDP probe responder, and an RT stream client that signs in as the joiner account), plus a `terraria signalprobe` instrument that activates signaling toward a hosting PS3 and logs every stanza and packet until mutual activation. Not yet wired into `serve`; the librudp handshake after mutual activation is still being decoded.

## v0.1.1 - 2026-11-07

`GET /healthz` (the website's `/healthz/terraria` and the status page read it).

## v0.1.0 - 2026-11-07

First service release (prds#157): `terraria serve` = the cross-play relay's Wii U leg on UDP 22950 (public game transport) and an
internal HTTP surface on 20260 (`/health`; `/internal/legs` POST/GET, bearer `TERRARIA_INTERNAL_KEY`) where the nex Terraria title
registers a leg (session key, host PID, core session) before a Wii U joins a cross room. Legs are matched to a console by the PIA
signature, recorded in Postgres (`relay_legs`: ids, timing, counters; no names, no keys). `TERRARIA_RELAY_GREET=1` makes legs act
as the Terraria host themselves (test mode until the PS3 leg forwards a real host). Image, quadlet sample (`openpak-terraria-core`),
port block 20260 and game port 22950.

## Before v0.1.0

- PIA Reliable protocol (24-byte header, sequences from 0xFFFFF82F, port 1) and update-mesh; host leg greets with Terraria PlayerId [00][slot] and answers Hello with [03][slot].
- M3 reached 2026-11-07 00:45 against Terraria (Wii U) in Quay: after join response + update-mesh + PlayerId the client sends Hello [01][13][01], then player info (4, 16, 50, 62x5) and 6 (request world info); screen "Requesting world information...". The update-mesh is what registers the host station on the joiner.

- PIA packet layer (`internal/pia`): packet header, messages (up to 5.4 format), AES-ECB, HMAC-MD5 keyed with the full session key (confirmed live).
- Station protocol v3 (connection request/response, inverse request, ack) and mesh join request/response; RTT and session-clock answers.
- `terraria join`: client leg (station handshake, NAT probe answers, mesh join) for joining a Wii U host; against Quay the host acks but does not open the inverse connection yet (NEX-side NAT traversal for the relay station not effective).
- `terraria probe -respond`: host leg W. Verified 2026-11-06 against Terraria (Wii U) in Quay: station handshake, mesh join accepted, PIA session held (RTT, clock, keepalive) while the game shows "Resetting game objects..." (prds#145).
