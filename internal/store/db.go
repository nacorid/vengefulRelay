package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"iter"

	"fiatjaf.com/nostr"
	"github.com/fiatjaf/eventstore/postgresql"
	_ "github.com/lib/pq"
	nbd "github.com/nbd-wtf/go-nostr"
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
			paid_at timestamp NOT NULL DEFAULT NOW()
		);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create invoices table: %w", err)
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
		ID: id.String(),
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

func (s *Storage) RegisterPayment(pubkey, txId, asset, amount, network, payer string) error {
	_, err := s.DB.Exec(
		"INSERT INTO invoices_paid (pubkey, transaction_id, asset, amount, network, payer) VALUES ($1, $2, $3, $4, $5, $6)",
		pubkey, txId, asset, amount, network, payer,
	)
	return err
}

func (s *Storage) PruneOldEvents(months int) {
	// postgresql backend has its own logic, but if you want raw deletion:
	// s.DB.Exec(`DELETE FROM event WHERE created_at < ...`)
	// For Khatru/Eventstore, usually you configure retention policies or run this separately.
}

func toNBDFilter(f nostr.Filter) nbd.Filter {
	var ids []string
	for _, id := range f.IDs {
		ids = append(ids, id.String())
	}
	var kinds []int
	for _, kind := range f.Kinds {
		kinds = append(kinds, int(kind.Num()))
	}
	var authors []string
	for _, author := range f.Authors {
		authors = append(authors, author.String())
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
	var tags nostr.Tags
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
	var tags nbd.Tags
	for _, t := range e.Tags {
		tags = append(tags, nbd.Tag(t))
	}

	// Convert [64]byte Sig back to hex string
	sig := hex.EncodeToString(e.Sig[:])

	return &nbd.Event{
		ID:        e.ID.String(),
		PubKey:    e.PubKey.String(),
		CreatedAt: nbd.Timestamp(e.CreatedAt),
		Kind:      int(e.Kind.Num()),
		Tags:      tags,
		Content:   e.Content,
		Sig:       sig,
	}
}
