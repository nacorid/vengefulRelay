package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/lightning"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"

	fnostr "fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"github.com/nbd-wtf/go-nostr"
)

type VengefulRelay struct {
	*khatru.Relay
	Config     config.Config
	Store      *store.Storage
	LNProvider *lightning.Provider
	logger     *slog.Logger
}

func New(cfg config.Config, st *store.Storage, ln *lightning.Provider) *VengefulRelay {
	r := khatru.NewRelay()

	vr := &VengefulRelay{
		Relay:      r,
		Config:     cfg,
		Store:      st,
		LNProvider: ln,
		logger:     slog.Default(),
	}

	pkey := fnostr.MustPubKeyFromHex(cfg.RelayPubkey)

	r.Info.Name = cfg.RelayName
	r.Info.PubKey = &pkey
	r.Info.Description = cfg.RelayDescription
	r.Info.URL = "https://relay.vengeful.eu"

	r.UseEventstore(st, 1000)

	if cfg.DeleteOldEvents && cfg.DeleteEventsOlderThan > 0 {
		go vr.runJanitor()
	}

	return vr
}

func (vr *VengefulRelay) rejectEventPolicy(ctx context.Context, evt *nostr.Event) (bool, string) {
	if vr.Config.FreeRelay {
		return false, "" // Accepted (false means do not reject)
	}

	// 1. Check Whitelist
	if slices.Contains(vr.Config.Whitelist, evt.PubKey) {
		return false, ""
	}

	// 2. Check Database for Payment
	if vr.Store.IsPubkeyRegistered(evt.PubKey) {
		return false, ""
	}

	// 3. Check Event Length
	jsonb, _ := json.Marshal(evt)
	if len(jsonb) > vr.Config.MaxEventLength {
		return true, "event too large"
	}

	// If we are here, they haven't paid
	return true, "payment required: visit " + vr.Info.URL
}

func (vr *VengefulRelay) runJanitor() {
	for {
		time.Sleep(60 * time.Minute)
		vr.logger.Debug("Running janitor...")
		_, err := vr.Store.DB.Exec(`DELETE FROM event WHERE created_at < $1`,
			time.Now().AddDate(0, -vr.Config.DeleteEventsOlderThan, 0).Unix())
		if err != nil {
			vr.logger.Error("Janitor error", "error", err)
		}
	}
}
