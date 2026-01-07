package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"

	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/lightning"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/khatru/policies"
	"fiatjaf.com/nostr/nip11"
)

type VengefulRelay struct {
	*khatru.Relay
	Config     config.Config
	Store      *store.Storage
	LNProvider *lightning.Provider
	logger     *slog.Logger
}

func New(cfg config.Config, st *store.Storage, ln *lightning.Provider, logger *slog.Logger) *VengefulRelay {
	if logger == nil {
		logger = slog.Default()
	}
	r := khatru.NewRelay()

	vr := &VengefulRelay{
		Relay:      r,
		Config:     cfg,
		Store:      st,
		LNProvider: ln,
		logger:     logger,
	}

	pkey := nostr.MustPubKeyFromHex(cfg.RelayPubkey)

	r.Info.Name = cfg.RelayName
	r.Info.PubKey = &pkey
	r.Info.Contact = cfg.ContactEmail
	r.Info.Description = cfg.RelayDescription
	r.Info.URL = cfg.RelayURL
	r.Info.Icon = cfg.RelayIcon
	r.Info.Fees = &nip11.RelayFeesDocument{
		Admission: []struct {
			Amount int    `json:"amount"`
			Unit   string `json:"unit"`
		}{
			{
				Amount: int(cfg.AdmissionFee),
				Unit:   "sats",
			},
		},
	}
	r.Info.PaymentsURL = cfg.RelayURL + "/invoice"
	r.Info.Software = "github.com/nacorid/vengefulRelay"
	r.Info.Version = "0.1.0"

	r.OnRequest = policies.SeqRequest(policies.AntiSyncBots, policies.NoEmptyFilters)
	r.OnEvent = policies.SeqEvent(vr.rejectEventPolicy)

	r.Log = slog.NewLogLogger(logger.Handler(), slog.LevelDebug)

	r.UseEventstore(st, 1000)

	return vr
}

func (vr *VengefulRelay) rejectEventPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	if vr.Config.FreeRelay {
		return false, "" // Accepted (false means do not reject)
	}

	// 1. Check Whitelist
	if slices.Contains(vr.Config.Whitelist, evt.PubKey.String()) {
		return false, ""
	}

	// 2. Check Database for Payment
	if vr.Store.IsPubkeyRegistered(evt.PubKey.String()) {
		return false, ""
	}

	// 3. Check Event Length
	jsonb, _ := json.Marshal(evt)
	if len(jsonb) > vr.Config.MaxEventLength {
		return true, "event too large"
	}

	// If we are here, they haven't paid
	return true, "payment required: visit " + vr.Info.PaymentsURL
}
