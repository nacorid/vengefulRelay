package relay

import (
	"context"
	"log/slog"

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
	LNProvider lightning.Provider
	logger     *slog.Logger
}

func New(cfg config.Config, st *store.Storage, ln lightning.Provider, logger *slog.Logger) *VengefulRelay {
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
	r.Info.Limitation = &nip11.RelayLimitationDocument{
		MaxMessageLength: cfg.MaxEventLength,
		MinPowDifficulty: cfg.MinPowDifficulty,
		AuthRequired:     true,
		PaymentRequired:  true,
		RestrictedWrites: true,
	}
	if cfg.Debug {
		r.Info.Fees = &nip11.RelayFeesDocument{
			Admission: []struct {
				Amount int    `json:"amount"`
				Unit   string `json:"unit"`
			}{
				{
					Amount: int(1),
					Unit:   "USDC",
				},
			},
		}

	} else {
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
	}
	r.Info.PaymentsURL = cfg.RelayURL
	r.Info.Software = "git.vengeful.eu/nacorid/vengefulRelay"
	r.Info.Version = "0.1.0"

	if cfg.Debug {
		r.OnRequest = policies.SeqRequest(vr.debugFilterPolicy, policies.AntiSyncBots, policies.NoEmptyFilters)
		r.OnEvent = policies.SeqEvent(
			vr.debugEventPolicy,
			vr.authPolicy,
			vr.nip62Policy,
			vr.signaturePolicy,
			vr.paymentPolicy,
			vr.eventLengthPolicy,
			vr.proofOfWorkPolicy,
			//vr.timestampPolicy,
		)
		r.OnConnect = func(ctx context.Context) { logger.Log(context.Background(), slog.Level(-8), "new client connected") }
	} else {
		//r.OnRequest = policies.SeqRequest(policies.AntiSyncBots, policies.NoEmptyFilters)
		r.OnEvent = policies.SeqEvent(
			vr.authPolicy,
			vr.nip62Policy,
			vr.signaturePolicy,
			vr.paymentPolicy,
			vr.eventLengthPolicy,
			vr.proofOfWorkPolicy,
			//vr.timestampPolicy,
		)
	}

	r.OnConnect = func(ctx context.Context) { khatru.RequestAuth(ctx) }

	r.Log = slog.NewLogLogger(logger.Handler(), slog.LevelDebug)

	r.UseEventstore(st, 1000)
	r.OnEventSaved = vr.afterEventStored

	//r.Negentropy = true

	r.ManagementAPI.AllowPubKey = vr.AllowPubKey
	r.ManagementAPI.BanPubKey = vr.BanPubKey
	r.ManagementAPI.ListAllowedPubKeys = vr.ListAllowedPubKeys
	r.ManagementAPI.ListBannedPubKeys = vr.ListBannedPubKeys

	r.Info.SupportedNIPs = []any{
		1,
		4,
		9,
		11,
		//13,
		15,
		17,
		25,
		40,
		42,
		45,
		56,
		62,
		70,
		//77,
		86,
	}

	return vr
}
