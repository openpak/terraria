# Changelog

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
