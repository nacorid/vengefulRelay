package relay

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip13"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
)

func (vr *VengefulRelay) authPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	pubkey, ok := khatru.GetAuthed(ctx)
	if !ok {
		khatru.RequestAuth(ctx)
		return true, "auth-required: please authenticate"
	}
	if pubkey != evt.PubKey && evt.Tags.ContainsAny("-", nil) {
		return true, ""
	}

	return false, ""
}

func (vr *VengefulRelay) signaturePolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	ok := evt.VerifySignature()
	if ok {
		return false, ""
	}
	return true, "invalid signature"
}

func (vr *VengefulRelay) paymentPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	// 1. Check Whitelist
	if slices.Contains(vr.Config.Whitelist, evt.PubKey.Hex()) {
		return false, ""
	}

	// 2. Check Database for Allowed or Banned
	_, pubkeyState, reason, err := vr.Store.QueryPubkeyState(evt.PubKey.Hex())
	if err != nil {
		return true, err.Error()
	}
	if pubkeyState == store.PubKeyAllowed {
		return false, ""
	}
	if pubkeyState == store.PubKeyBanned {
		return true, reason
	}

	// 3. Check Database for Payment
	if vr.Store.IsPubkeyRegistered(evt.PubKey.Hex()) {
		return false, ""
	}

	if vr.Config.FreeRelay {
		return false, ""
	}

	// If we are here, they haven't paid
	return true, "payment-required: visit " + vr.Info.PaymentsURL
}

func (vr *VengefulRelay) eventLengthPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	jsonb, _ := json.Marshal(evt)
	if len(jsonb) > vr.Config.MaxEventLength {
		return true, "event too large"
	}
	return false, ""
}

func (vr *VengefulRelay) proofOfWorkPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	if err := nip13.Check(evt.ID, vr.Config.MinPowDifficulty); err != nil {
		return true, "pow: difficulty 20 required"
	}
	return false, ""
}

func (vr *VengefulRelay) timestampPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	now := time.Now()
	if evt.CreatedAt.Time().After(now.Add(15 * time.Minute)) {
		return true, "invalid: timestamp in future"
	}
	if evt.CreatedAt.Time().Before(now.Add(-48 * time.Hour)) {
		return true, "invalid: timestamp too old"
	}
	return false, ""
}
