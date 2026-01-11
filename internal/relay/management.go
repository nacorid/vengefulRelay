package relay

import (
	"context"
	"fmt"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip86"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
)

func (vr *VengefulRelay) allowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.Store.AllowPubKey(ctx, pubkey.Hex(), store.PubKeyAllowed, reason)
}

func (vr *VengefulRelay) banPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.Store.AllowPubKey(ctx, pubkey.Hex(), store.PubKeyBanned, reason)
}

func (vr *VengefulRelay) listAllowedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	pubkeys, reasons, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAllowed)
	if err != nil {
		return nil, err
	}

	result := make([]nip86.PubKeyReason, 0, len(pubkeys))
	for i, pk := range pubkeys {
		result = append(result, nip86.PubKeyReason{
			PubKey: pk,
			Reason: reasons[i],
		})
	}

	return result, nil
}

func (vr *VengefulRelay) listBannedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}

	pubkeys, reasons, err := vr.Store.QueryAllPubkeyStates(store.PubKeyBanned)
	if err != nil {
		return nil, err
	}

	result := make([]nip86.PubKeyReason, 0, len(pubkeys))
	for i, pk := range pubkeys {
		result = append(result, nip86.PubKeyReason{
			PubKey: pk,
			Reason: reasons[i],
		})
	}

	return result, nil
}
