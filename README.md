# terraria

OpenPak's one Terraria service for every console (owner rule: one game service per game). It owns the Terraria session catalogue
on top of the matchmaking core, the compatibility groups (`old-gen-1.2.4`: PS3, Wii U, Xbox 360; `current-1.4`: Switch, PS4), the
cross-play policy (always on) and the relay that carries the game between consoles. Console adapters (the nex Terraria title,
np-matching2) speak each console's protocol and ask this service what to list, what to join and how to route.

Plan: `prds/repos/terraria-crossplay-plan.md` (private). Cards: openpak/prds#145 (cross-play), #157 (this service).

## State

- `internal/pia`: the PIA packet layer Terraria (Wii U) uses (PIA 3.x: 12-byte header, messages up to the 5.4 format, AES-128-ECB
  + HMAC-MD5 with the NEX session key). Layouts from github.com/kinnay/NintendoClients/wiki.
- `terraria probe`: listens where a Wii U is told the host is (the nex title's `TERRARIA_RELAY_STATION`), decrypts with the
  session key and writes every packet to a JSON-lines capture. The start of the relay's Wii U leg.

## Run

`terraria serve` (default). Ports: block 20260 (HTTP 20260, internal), game transport UDP 22950 (public). Environment:
`TERRARIA_HTTP_ADDR` (:20260), `TERRARIA_RELAY_ADDR` (:22950), `TERRARIA_RELAY_PUBLIC` (the ip:port consoles are given),
`TERRARIA_DATABASE_URL` (Postgres, table `relay_legs`), `TERRARIA_INTERNAL_KEY` (bearer for `/internal/*`),
`TERRARIA_RELAY_GREET=1` (test only). Quadlet sample: `deploy/openpak-terraria-core.container`. Logs: one line per request and per
relay event on stdout (the host's collector files them per service per day).

## Build and test

    GOWORK=off go vet ./... && GOWORK=off go test ./...

License: AGPL-3.0-only.
