package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"strings"

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
			fee text NOT NULL,
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
	return func(yield func(nostr.Event) bool) {
		// 1. Build the SQL query
		query, params, err := buildEventQuery(f)
		if err != nil {
			return
		}

		rows, err := s.PostgresBackend.DB.QueryContext(context.Background(), query, params...)
		if err != nil {
			return
		}
		defer rows.Close()

		for rows.Next() {
			var evt nostr.Event
			var timestamp int64

			var idStr, pubkeyStr, sigStr string
			var tagsBytes []byte

			err := rows.Scan(
				&idStr,
				&pubkeyStr,
				&timestamp,
				&evt.Kind,
				&tagsBytes,
				&evt.Content,
				&sigStr,
			)
			if err != nil {
				continue
			}

			// --- Type Conversion ---
			if idVal, err := nostr.IDFromHex(idStr); err == nil {
				evt.ID = idVal
			} else {
				continue
			}
			if pkVal, err := nostr.PubKeyFromHex(pubkeyStr); err == nil {
				evt.PubKey = pkVal
			} else {
				continue
			}
			sigBytes, err := hex.DecodeString(sigStr)
			if err == nil && len(sigBytes) == 64 {
				copy(evt.Sig[:], sigBytes)
			}

			evt.CreatedAt = nostr.Timestamp(timestamp)

			if err := json.Unmarshal(tagsBytes, &evt.Tags); err != nil {
				continue
			}

			if !yield(evt) {
				return
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

func (s *Storage) RegisterPayment(pubkey, txId, asset, amount, network, payer, fee string) error {
	_, err := s.DB.Exec(
		"INSERT INTO invoices_paid (pubkey, transaction_id, asset, amount, network, payer, fee) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		pubkey, txId, asset, amount, network, payer, fee,
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

func (s *Storage) VanishPubKey(ctx context.Context, pubkey string) error {
	var ret error
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM known_pubkeys WHERE pubkey = $1`,
		pubkey,
	)
	if err != nil {
		ret = fmt.Errorf("Failed to vanish pubkey %s from known_pubkeys: %w", pubkey, err)
	}
	_, err = s.DB.ExecContext(ctx,
		`DELETE FROM invoices_paid WHERE pubkey = $1`,
		pubkey,
	)
	if err != nil {
		ret = fmt.Errorf("%w\nFailed to vanish pubkey %s from invoices_paid: %w", ret, pubkey, err)
	}
	_, err = s.DB.ExecContext(ctx,
		`DELETE FROM event WHERE pubkey = $1`,
		pubkey,
	)
	if err != nil {
		ret = fmt.Errorf("%w\nFailed to vanish pubkey %s from events: %w", ret, pubkey, err)
	}
	return ret
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

func buildEventQuery(filter nostr.Filter) (string, []any, error) {
	var conditions []string
	var params []any

	addParam := func(val any) string {
		params = append(params, val)
		return fmt.Sprintf("$%d", len(params))
	}

	if len(filter.IDs) > 0 {
		var ph []string
		for _, id := range filter.IDs {
			ph = append(ph, addParam(id.Hex()))
		}
		conditions = append(conditions, fmt.Sprintf("id IN (%s)", strings.Join(ph, ",")))
	}

	if len(filter.Authors) > 0 {
		var ph []string
		for _, pk := range filter.Authors {
			ph = append(ph, addParam(pk.Hex()))
		}
		conditions = append(conditions, fmt.Sprintf("pubkey IN (%s)", strings.Join(ph, ",")))
	}

	if len(filter.Kinds) > 0 {
		var ph []string
		for _, k := range filter.Kinds {
			ph = append(ph, addParam(k))
		}
		conditions = append(conditions, fmt.Sprintf("kind IN (%s)", strings.Join(ph, ",")))
	}

	for _, values := range filter.Tags {
		if len(values) == 0 {
			continue
		}
		var ph []string
		for _, val := range values {
			ph = append(ph, addParam(val))
		}
		conditions = append(conditions, fmt.Sprintf("tagvalues && ARRAY[%s]", strings.Join(ph, ",")))
	}

	if filter.Since != 0 {
		conditions = append(conditions, fmt.Sprintf("created_at >= %s", addParam(filter.Since)))
	}
	if filter.Until != 0 {
		conditions = append(conditions, fmt.Sprintf("created_at <= %s", addParam(filter.Until)))
	}

	if len(conditions) == 0 {
		conditions = append(conditions, "true")
	}

	limit := 100
	if filter.Limit > 0 && filter.Limit < 1000 {
		limit = filter.Limit
	}

	query := fmt.Sprintf(`
		SELECT id, pubkey, created_at, kind, tags, content, sig
		FROM event 
		WHERE %s 
		ORDER BY created_at DESC, id ASC 
		LIMIT %d`,
		strings.Join(conditions, " AND "),
		limit,
	)

	return query, params, nil
}
