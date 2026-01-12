package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"iter"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"github.com/fiatjaf/eventstore/postgresql"
	_ "github.com/lib/pq"
	nbd "github.com/nbd-wtf/go-nostr"
)

var _ eventstore.Store = (*Storage)(nil)

type PubKeyState int

const (
	PubKeyUnknown PubKeyState = iota
	PubKeyAllowed
	PubKeyBanned
)

type Storage struct {
	*postgresql.PostgresBackend
}

func Init(databaseURL string) (*Storage, error) {
	db := &postgresql.PostgresBackend{DatabaseURL: databaseURL}

	rawDB, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw db connection: %w", err)
	}
	defer rawDB.Close()

	_, err = rawDB.Exec(`
		CREATE TABLE IF NOT EXISTS invoices_paid (
  			pubkey text NOT NULL,
  			transaction_id text NOT NULL,
			asset text NOT NULL,
			amount text NOT NULL,
			network text NOT NULL,
			payer text NOT NULL,
			paid_at timestamp NOT NULL DEFAULT NOW(),
			PRIMARY KEY (pubkey, transaction_id)
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create invoices table: %w", err)
	}

	_, err = rawDB.Exec(`
		CREATE TABLE IF NOT EXISTS known_pubkeys (
			pubkey  text PRIMARY KEY,
			allowed boolean NOT NULL DEFAULT false,
			banned  boolean NOT NULL DEFAULT false,
			reason  text,
			CHECK (NOT (allowed AND banned))
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create allowlist table: %w", err)
	}

	err = db.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to init eventstore backend: %w", err)
	}
	return &Storage{PostgresBackend: db}, nil
}

func (s *Storage) CountEvents(f nostr.Filter) (uint32, error) {
	filter := toNBDFilter(f)
	i64, err := s.PostgresBackend.CountEvents(context.Background(), filter)
	return uint32(i64), err
}

func (s *Storage) DeleteEvent(id nostr.ID) error {
	event := &nbd.Event{
		ID: id.Hex(),
	}
	return s.PostgresBackend.DeleteEvent(context.Background(), event)
}

func (s *Storage) QueryEvents(f nostr.Filter, i int) iter.Seq[nostr.Event] {
	filter := toNBDFilter(f)

	ch, err := s.PostgresBackend.QueryEvents(context.Background(), filter)
	if err != nil {
		return nil
	}

	// 3. Convert Channel to Iterator
	return func(yield func(nostr.Event) bool) {
		for oldEvt := range ch {
			// Convert back to new Event
			newEvt := fromNbdEvent(oldEvt)
			if !yield(newEvt) {
				return // Stop iteration if caller says so
			}
		}
	}
}

func (s *Storage) ReplaceEvent(e nostr.Event) error {
	event := toNbdEvent(&e)
	return s.PostgresBackend.ReplaceEvent(context.Background(), event)
}

func (s *Storage) SaveEvent(e nostr.Event) error {
	event := toNbdEvent(&e)
	return s.PostgresBackend.SaveEvent(context.Background(), event)
}

func (s *Storage) IsPubkeyRegistered(pubkey string) bool {
	var exists bool
	err := s.DB.QueryRow("SELECT EXISTS (SELECT 1 FROM invoices_paid WHERE pubkey = $1)", pubkey).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (s *Storage) QueryPubkeyState(pubkey string) (nostr.PubKey, PubKeyState, string, error) {
	var (
		pubkeyHex string
		allowed   bool
		banned    bool
		reason    sql.NullString
	)

	err := s.DB.QueryRow(`
		SELECT pubkey, allowed, banned, reason
		FROM known_pubkeys
		WHERE pubkey = $1
	`, pubkey).Scan(&pubkeyHex, &allowed, &banned, &reason)

	if err != nil {
		if err == sql.ErrNoRows {
			return nostr.PubKey{}, PubKeyUnknown, "", nil
		}
		return nostr.PubKey{}, PubKeyUnknown, "", err
	}

	pk := nostr.MustPubKeyFromHex(pubkeyHex)

	switch {
	case banned:
		return pk, PubKeyBanned, reason.String, nil
	case allowed:
		return pk, PubKeyAllowed, "", nil
	default:
		return pk, PubKeyUnknown, "", nil
	}
}

func (s *Storage) QueryAllPubkeyStates(state PubKeyState) ([]nostr.PubKey, []string, error) {
	var (
		rows *sql.Rows
		err  error
	)

	switch state {
	case PubKeyAllowed:
		rows, err = s.DB.Query(`
			SELECT pubkey, reason
			FROM known_pubkeys
			WHERE allowed = true
		`)
	case PubKeyBanned:
		rows, err = s.DB.Query(`
			SELECT pubkey, reason
			FROM known_pubkeys
			WHERE banned = true
		`)
	case PubKeyUnknown:
		rows, err = s.DB.Query(`
			SELECT pubkey, NULL
			FROM known_pubkeys
			WHERE allowed = false
			  AND banned = false
		`)
	default:
		return nil, nil, fmt.Errorf("invalid pubkey state: %v", state)
	}

	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var (
		pubkeys []nostr.PubKey
		reasons []string
	)

	for rows.Next() {
		var (
			pubkeyHex string
			reason    sql.NullString
		)

		if err := rows.Scan(&pubkeyHex, &reason); err != nil {
			return nil, nil, err
		}

		pubkeys = append(pubkeys, nostr.MustPubKeyFromHex(pubkeyHex))
		reasons = append(reasons, reason.String)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return pubkeys, reasons, nil
}

func (s *Storage) RegisterPayment(pubkey, txId, asset, amount, network, payer string) error {
	_, err := s.DB.Exec(
		"INSERT INTO invoices_paid (pubkey, transaction_id, asset, amount, network, payer) VALUES ($1, $2, $3, $4, $5, $6)",
		pubkey, txId, asset, amount, network, payer,
	)
	return err
}

func (s *Storage) ChangePubKeyState(ctx context.Context, pubkey string, pubkeyState PubKeyState, reason string) error {
	var allowed, banned bool
	switch pubkeyState {
	case PubKeyAllowed:
		allowed = true
		banned = false
	case PubKeyBanned:
		allowed = false
		banned = true
	default:
		allowed = false
		banned = false
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO known_pubkeys (pubkey, allowed, banned, reason) VALUES ($1, $2, $3, $4)
		ON CONFLICT (pubkey) DO UPDATE
		SET
			allowed  = EXCLUDED.allowed,
			banned   = EXCLUDED.banned,
			reason   = EXCLUDED.reason`,
		pubkey, allowed, banned, reason,
	)
	return err
}

func toNBDFilter(f nostr.Filter) nbd.Filter {
	var ids []string
	for _, id := range f.IDs {
		ids = append(ids, id.Hex())
	}
	var kinds []int
	for _, kind := range f.Kinds {
		kinds = append(kinds, int(kind.Num()))
	}
	var authors []string
	for _, author := range f.Authors {
		authors = append(authors, author.Hex())
	}
	return nbd.Filter{
		IDs:     ids,
		Kinds:   kinds,
		Authors: authors,
		Tags:    nbd.TagMap(f.Tags),
		Since:   (*nbd.Timestamp)(&f.Since),
		Until:   (*nbd.Timestamp)(&f.Until),
		Limit:   f.Limit,
		Search:  f.Search,
	}
}

func fromNbdEvent(e *nbd.Event) nostr.Event {
	if e == nil {
		return nostr.Event{}
	}
	tags := make(nostr.Tags, 0)
	for _, t := range e.Tags {
		tags = append(tags, nostr.Tag(t))
	}
	var sig [64]byte
	b, _ := hex.DecodeString(e.Sig)
	copy(sig[:], b)
	return nostr.Event{
		ID:        nostr.MustIDFromHex(e.ID),
		PubKey:    nostr.MustPubKeyFromHex(e.PubKey),
		CreatedAt: nostr.Timestamp(e.CreatedAt),
		Kind:      nostr.Kind(e.Kind),
		Tags:      tags,
		Content:   e.Content,
		Sig:       sig,
	}
}

func toNbdEvent(e *nostr.Event) *nbd.Event {
	if e == nil {
		return nil
	}
	tags := make(nbd.Tags, 0)
	for _, t := range e.Tags {
		tags = append(tags, nbd.Tag(t))
	}

	// Convert [64]byte Sig back to hex string
	sig := hex.EncodeToString(e.Sig[:])

	return &nbd.Event{
		ID:        e.ID.Hex(),
		PubKey:    e.PubKey.Hex(),
		CreatedAt: nbd.Timestamp(e.CreatedAt),
		Kind:      int(e.Kind.Num()),
		Tags:      tags,
		Content:   e.Content,
		Sig:       sig,
	}
}
