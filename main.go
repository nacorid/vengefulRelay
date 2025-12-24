package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/relayer/v2"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
)

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
