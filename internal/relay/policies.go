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
		return true, ""
	}

	return false, ""
}

func (vr *VengefulRelay) signaturePolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	ok := evt.VerifySignature()
	if ok {
		return false, ""
	}
	return true, "blocked: invalid signature"
}

func (vr *VengefulRelay) paymentPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	// 1. Check Whitelist
	if slices.Contains(vr.Config.Whitelist, evt.PubKey.Hex()) {
		return false, ""
	}

	if evt.Kind == 62 {
		return false, ""
	}

	if (evt.Kind == 4 || evt.Kind == 1059) && evt.Tags.ContainsAny("p", nil) {
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
		return true, fmt.Sprintf("restricted: nip13 difficulty %d required", vr.Config.MinPowDifficulty)
	}
	return false, ""
}

func (vr *VengefulRelay) timestampPolicy(ctx context.Context, evt nostr.Event) (bool, string) {
	now := time.Now()
	if evt.CreatedAt.Time().After(now.Add(15 * time.Minute)) {
		return true, "blocked: timestamp in future"
	}
	if evt.CreatedAt.Time().Before(now.Add(-48 * time.Hour)) {
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
	// We normalize (remove trailing slash, ignore scheme if needed) for better matching
	myURL := normalizeURL(vr.Config.RelayURL)
	targetURL := normalizeURL(targetRelay)

	if myURL != targetURL {
		// NIP-62 says: "Relays... SHOULD NOT operate on requests not targeting them."
		// We reject it so we don't store a vanish request meant for someone else.
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
