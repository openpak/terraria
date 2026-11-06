# Changelog

## Unreleased

- PIA packet layer (`internal/pia`): packet header, messages (up to 5.4 format), AES-ECB, HMAC-MD5 keyed with the full session key (confirmed live).
- Station protocol v3 (connection request/response, inverse request, ack) and mesh join request/response; RTT and session-clock answers.
- `terraria join`: client leg (station handshake, NAT probe answers, mesh join) for joining a Wii U host; against Quay the host acks but does not open the inverse connection yet (NEX-side NAT traversal for the relay station not effective).
- `terraria probe -respond`: host leg W. Verified 2026-11-06 against Terraria (Wii U) in Quay: station handshake, mesh join accepted, PIA session held (RTT, clock, keepalive) while the game shows "Resetting game objects..." (prds#145).
