// Package store keeps the relay's durable record: one row per relay leg (a console's connection carried by the relay), with its
// session ids, timing and counters. Ids only: no names, no keys (owner rule: everything permanent in Postgres, no identity copies).
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = `CREATE TABLE IF NOT EXISTS relay_legs (
	id           bigserial PRIMARY KEY,
	network      text NOT NULL,          -- the console's network on this leg ("wiiu", "np")
	core_session text NOT NULL,          -- matchmaking core session the leg belongs to
	gathering    bigint NOT NULL DEFAULT 0,
	host_pid     bigint NOT NULL DEFAULT 0,
	joiner_pid   bigint NOT NULL DEFAULT 0,
	peer         text NOT NULL DEFAULT '',
	created      timestamptz NOT NULL DEFAULT now(),
	connected    timestamptz,
	ended        timestamptz,
	end_reason   text NOT NULL DEFAULT '',
	packets_in   bigint NOT NULL DEFAULT 0,
	packets_out  bigint NOT NULL DEFAULT 0,
	game_msgs_in bigint NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS relay_legs_open ON relay_legs (created) WHERE ended IS NULL;`

type Store struct{ DB *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	// legs left open by a previous process ended with it
	db.Exec(ctx, `UPDATE relay_legs SET ended=now(), end_reason='restart' WHERE ended IS NULL`)
	return &Store{DB: db}, nil
}

func (s *Store) Close() { s.DB.Close() }

// Leg is one registered relay leg.
type Leg struct {
	ID          int64
	Network     string
	CoreSession string
	Gathering   int64
	HostPID     int64
	JoinerPID   int64
}

func (s *Store) CreateLeg(ctx context.Context, l Leg) (int64, error) {
	var id int64
	err := s.DB.QueryRow(ctx, `INSERT INTO relay_legs (network, core_session, gathering, host_pid, joiner_pid) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		l.Network, l.CoreSession, l.Gathering, l.HostPID, l.JoinerPID).Scan(&id)
	return id, err
}

func (s *Store) Connected(ctx context.Context, id int64, peer string) error {
	_, err := s.DB.Exec(ctx, `UPDATE relay_legs SET connected=now(), peer=$2 WHERE id=$1`, id, peer)
	return err
}

func (s *Store) Counters(ctx context.Context, id, in, out, game int64) error {
	_, err := s.DB.Exec(ctx, `UPDATE relay_legs SET packets_in=$2, packets_out=$3, game_msgs_in=$4 WHERE id=$1`, id, in, out, game)
	return err
}

func (s *Store) End(ctx context.Context, id int64, reason string) error {
	_, err := s.DB.Exec(ctx, `UPDATE relay_legs SET ended=now(), end_reason=$2 WHERE id=$1 AND ended IS NULL`, id, reason)
	return err
}

// Open legs started within d.
func (s *Store) OpenLegs(ctx context.Context) ([]Leg, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, network, core_session, gathering, host_pid, joiner_pid FROM relay_legs WHERE ended IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Leg
	for rows.Next() {
		var l Leg
		if err := rows.Scan(&l.ID, &l.Network, &l.CoreSession, &l.Gathering, &l.HostPID, &l.JoinerPID); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

var _ = time.Second
