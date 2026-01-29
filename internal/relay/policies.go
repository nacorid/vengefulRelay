package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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
		vr.logger.Debug("auth failed: protected event for other user", "event_pubkey", evt.PubKey, "authed_as", pubkey, "Kind", evt.Kind, "content", evt.Content, "tags", evt.Tags)
		return true, "restricted: cannot post protected events for other users"
	}
	vr.logger.Debug("auth success", "event_pubkey", evt.PubKey, "authed_as", pubkey, "Kind", evt.Kind, "content", evt.Content, "tags", evt.Tags)
	return false, ""
}

func (vr *VengefulRelay) debugEventPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	pubkey, ok := khatru.GetAuthed(ctx)
	if !ok {
		return false, ""
	}
	vr.logger.Debug("event received", "pubkey", pubkey, "event", evt)
	return false, ""
}

func (vr *VengefulRelay) debugFilterPolicy(ctx context.Context, flt nostr.Filter) (bool, string) {
	pubkey, ok := khatru.GetAuthed(ctx)
	if !ok {
		return false, ""
	}
	vr.logger.Debug("request received", "pubkey", pubkey, "filter", flt)
	return false, ""
}

func (vr *VengefulRelay) signaturePolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	ok := evt.VerifySignature()
	if ok {
		return false, ""
	}
	vr.logger.Debug("invalid signature", "event_id", evt.ID, "event_pubkey", evt.PubKey)
	return true, "blocked: invalid signature"
}

func (vr *VengefulRelay) paymentPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	// 1. Check Whitelist
	if slices.Contains(vr.Config.Whitelist, evt.PubKey.Hex()) {
		//vr.logger.Debug("whitelisted pubkey", "pubkey", evt.PubKey.Hex())
		return false, ""
	}

	if evt.Kind == 62 {
		//vr.logger.Debug("NIP-62 Vanish event, allowing", "pubkey", evt.PubKey.Hex())
		return false, ""
	}

	// 2. Check Database for Allowed or Banned
	_, pubkeyState, reason, err := vr.Store.QueryPubkeyState(evt.PubKey.Hex())
	if err != nil {
		return true, fmt.Sprintf("restricted: %v", err)
	}
	if pubkeyState == store.PubKeyAllowed {
		//vr.logger.Debug("allowed pubkey", "pubkey", evt.PubKey.Hex())
		return false, ""
	}
	if pubkeyState == store.PubKeyBanned {
		return true, fmt.Sprintf("restricted: %s", reason)
	}

	// 3. Check Database for Payment
	if vr.Store.IsPubkeyRegistered(evt.PubKey.Hex()) {
		vr.logger.Debug("paid pubkey", "pubkey", evt.PubKey.Hex())
		return false, ""
	}

	if vr.Config.FreeRelay {
		return false, ""
	}

	if (evt.Kind == 4 || evt.Kind == 1059) && evt.Tags.ContainsAny("p", nil) {
		//vr.logger.Debug("payment event kind, allowing", "pubkey", evt.PubKey.Hex(), "kind", evt.Kind)
		return false, ""
	}

	// If we are here, they haven't paid
	return true, "payment-required: visit " + vr.Info.PaymentsURL
}

func (vr *VengefulRelay) eventLengthPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	jsonb, _ := json.Marshal(evt)
	if len(jsonb) > vr.Config.MaxEventLength {
		vr.logger.Debug("event too large", "pubkey", evt.PubKey.Hex(), "size", len(jsonb))
		return true, "blocked: event too large"
	}
	return false, ""
}

func (vr *VengefulRelay) proofOfWorkPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	if evt.Kind == 62 {
		return false, ""
	}
	err := nip13.Check(evt.ID, vr.Config.MinPowDifficulty)
	if err != nil {
		vr.logger.Debug("pow check failed", "err", err, "event_id", evt.ID)
		return true, fmt.Sprintf("restricted: nip13 difficulty %d required", vr.Config.MinPowDifficulty)
	}
	return false, ""
}

func (vr *VengefulRelay) timestampPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	now := time.Now()
	if evt.CreatedAt.Time().After(now.Add(15 * time.Minute)) {
		vr.logger.Debug("event from future", "pubkey", evt.PubKey.Hex(), "created_at", evt.CreatedAt.Time(), "now", now)
		return true, "blocked: timestamp in future"
	}
	if evt.CreatedAt.Time().Before(now.Add(-48 * time.Hour)) {
		vr.logger.Debug("event too old", "pubkey", evt.PubKey.Hex(), "created_at", evt.CreatedAt.Time(), "now", now)
		return true, "blocked: timestamp too old"
	}
	return false, ""
}

// nip62Policy validates that a Request to Vanish targets THIS relay.
func (vr *VengefulRelay) nip62Policy(ctx context.Context, evt nostr.Event) (bool, string) {
	if evt.Kind != 62 {
		return false, ""
	}
	pubkey, ok := khatru.GetAuthed(ctx)
	if !ok {
		khatru.RequestAuth(ctx)
		return true, "auth-required: please authenticate"
	}
	if pubkey != evt.PubKey {
		return true, "blocked: must be author of NIP-62 vanish request"
	}

	if evt.VerifySignature() == false {
		return true, "blocked: invalid signature on NIP-62 vanish request"
	}

	// 1. Find the "relay" tag
	targetRelay := ""
	for _, tag := range evt.Tags {
		if len(tag) >= 2 && tag[0] == "relay" {
			targetRelay = tag[1]
			break
		}
	}

	if targetRelay == "" {
		return true, "blocked: kind 62 missing 'relay' tag"
	}

	if targetRelay == "ALL_RELAYS" {
		return false, ""
	}

	// 2. Compare against our Config.RelayURL
	myURL := normalizeURL(vr.Config.RelayURL)
	targetURL := normalizeURL(targetRelay)

	if myURL != targetURL {
		return true, "blocked: vanish request not targeting this relay"
	}

	// Validation passed.
	return false, ""
}

// normalizeURL is a helper to compare relay URLs loosely (ws:// == wss:// == https://)
func normalizeURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, "/")
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	return u
}
