package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/relayer/v2"
	"github.com/kelseyhightower/envconfig"
	"github.com/nbd-wtf/go-nostr"
)

var _ relayer.Relay = (*Relay)(nil)

type Relay struct {
	PostgresDatabase      string   `required:"true" envconfig:"POSTGRESQL_DATABASE"`
	RelayName             string   `default:"Vengeful Relay" envconfig:"RELAY_NAME"`
	ListeningAddress      string   `default:"0.0.0.0" envconfig:"LISTENGING_ADDRESS"`
	Port                  int      `default:"7447" envconfig:"PORT"`
	MaxEventLength        int      `default:"100000" envconfig:"MAX_EVENT_LENGTH"`
	DeleteOldEvents       bool     `default:"false" envconfig:"DELETE_OLD_EVENTS"`
	DeleteEventsOlderThan int      `default:"3" envconfig:"DELETE_EVENTS_OLDER_THAN"`
	Whitelist             []string `envconfig:"WHITELIST"`
	FreeRelay             bool     `default:"true" envconfig:"FREE_RELAY"`
	CLNNodeId             string   `envconfig:"CLN_NODE_ID"`
	CLNHost               string   `envconfig:"CLN_HOST"`
	CLNRune               string   `envconfig:"CLN_RUNE"`
	TicketPriceSats       int64    `envconfig:"TICKET_PRICE_SATS"`
	CDPAPIKeyName         string   `envconfig:"CDP_API_KEY_NAME"`
	CDPAPIKeySecret       string   `envconfig:"CDP_API_KEY_SECRET"`
	EVMWallet             string   `envconfig:"EVM_WALLET"`
	SVMWallet             string   `envconfig:"SVM_WALLET"`
	CDPClientKey          string   `envconfig:"CDP_CLIENT_KEY"`

	storage *postgresql.PostgresBackend
}

func (r *Relay) Name() string {
	return r.RelayName
}

func (r *Relay) Storage(ctx context.Context) eventstore.Store {
	return r.storage
}

func (r *Relay) Init() error {
	err := envconfig.Process("", r)
	if err != nil {
		return fmt.Errorf("couldn't process envconfig: %w", err)
	}

	r.storage.Exec(`
		CREATE TABLE IF NOT EXISTS invoices_paid (
  			pubkey text NOT NULL,
  			transaction_id text NOT NULL,
			asset text NOT NULL,
			amount text NOT NULL,
			network text NOT NULL,
			payer text not NULL
		);
	`)

	// every hour, delete all very old events if Environment variable is set
	if r.DeleteOldEvents {
		go func() {
			db := r.Storage(context.TODO()).(*postgresql.PostgresBackend)
			months := r.DeleteEventsOlderThan
			for {
				time.Sleep(60 * time.Minute)
				db.DB.Exec(`DELETE FROM event WHERE created_at < $1`, time.Now().AddDate(0, -months, 0).Unix())
			}
		}()
	}

	return nil
}

func (r *Relay) AcceptEvent(ctx context.Context, evt *nostr.Event) (bool, string) {
	accept := false
	if r.FreeRelay {
		accept = true
	} else {
		// allow whitelisted pubkeys
		if slices.Contains(r.Whitelist, evt.PubKey) {
			accept = true
		}
	}
	if !accept {
		accept = checkInvoicePaidOk(ctx, r.storage, evt.PubKey)
	}
	if !accept {
		accept = checkLndInvoicePaidOk(r, evt.PubKey)
	}
	// block events that are too large
	jsonb, _ := json.Marshal(evt)
	if len(jsonb) > r.MaxEventLength {
		return false, "event too large"
	}
	if !accept {
		return false, "payment required"
	}
	return true, ""
}

func checkInvoicePaidOk(ctx context.Context, store *postgresql.PostgresBackend, pubkey string) bool {
	var exists bool
	err := store.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM invoices_paid WHERE pubkey = $1)", pubkey).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}
