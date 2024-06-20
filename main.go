package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/relayer/v2"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"github.com/nbd-wtf/go-nostr"
)

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

func (r *Relay) AcceptEvent(ctx context.Context, evt *nostr.Event) bool {
	accept := false
	if r.FreeRelay {
		accept = true
	} else {
		// allow whitelisted pubkeys
		for _, pubkey := range r.Whitelist {
			if pubkey == evt.PubKey {
				accept = true
				break
			}
		}
	}
	if !accept {
		accept = checkInvoicePaidOk(r, evt.PubKey)
	}
	// block events that are too large
	jsonb, _ := json.Marshal(evt)
	return accept && len(jsonb) <= r.MaxEventLength
}

func main() {
	r := Relay{}
	if err := envconfig.Process("", &r); err != nil {
		log.Fatalf("failed to read from env: %v", err)
		return
	}
	if r.DeleteEventsOlderThan < 0 && r.DeleteOldEvents {
		log.Fatalf("cannot delete events from the future")
		return
	}
	if r.MaxEventLength <= 0 {
		log.Fatalf("cannot accept events with length <= 0")
		return
	}
	r.storage = &postgresql.PostgresBackend{DatabaseURL: r.PostgresDatabase}
	server, err := relayer.NewServer(&r)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}
	// special handlers
	server.Router().HandleFunc("/", handleWebpage)
	server.Router().HandleFunc("/invoice", func(w http.ResponseWriter, rq *http.Request) {
		handleInvoice(w, rq, &r)
	})
	if err := server.Start(r.ListeningAddress, r.Port); err != nil {
		log.Fatalf("server terminated: %v", err)
	}
}
