package relay

import (
	"context"
	"fmt"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip86"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
)

func (vr *VengefulRelay) AllowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.InternalChangePubKey(ctx, pubkey.Hex(), store.PubKeyAllowed, reason)
}

func (vr *VengefulRelay) InternalChangePubKey(ctx context.Context, pubkey string, state store.PubKeyState, reason string) error {
	return vr.Store.ChangePubKeyState(ctx, pubkey, state, reason)
}

func (vr *VengefulRelay) BanPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.InternalChangePubKey(ctx, pubkey.Hex(), store.PubKeyBanned, reason)
}

func (vr *VengefulRelay) ListAllowedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	return vr.InternalListPubKeys(store.PubKeyAllowed)
}

func (vr *VengefulRelay) InternalListPubKeys(state store.PubKeyState) ([]nip86.PubKeyReason, error) {
	pubkeys, reasons, err := vr.Store.QueryAllPubkeyStates(state)
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

func (vr *VengefulRelay) ListBannedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	return vr.InternalListPubKeys(store.PubKeyBanned)
}
