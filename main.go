package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/relayer/v2"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
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
		accept = checkInvoicePaidOk(r, evt.PubKey)
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

func main() {
	logger := slog.Default()
	r := Relay{}
	if err := envconfig.Process("", &r); err != nil {
		logger.Error("failed to read from env", "error", err)
		os.Exit(1)
	}
	if r.DeleteEventsOlderThan < 0 && r.DeleteOldEvents {
		logger.Error("cannot delete events from the future")
		os.Exit(1)
	}
	if r.MaxEventLength <= 0 {
		logger.Error("cannot accept events with length <= 0")
		os.Exit(1)
	}

	r.storage = &postgresql.PostgresBackend{DatabaseURL: r.PostgresDatabase}
	server, err := relayer.NewServer(&r)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	// special handlers
	server.Router().HandleFunc("/", handleWebpage)
	server.Router().HandleFunc("/invoice", func(w http.ResponseWriter, rq *http.Request) {
		handleInvoice(w, rq, &r)
	})
	if err := server.Start(r.ListeningAddress, r.Port); err != nil {
		logger.Error("server terminated", "error", err)
	}
}
