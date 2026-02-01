package relay

import (
	"context"
	"fmt"
	"slices"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip86"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
)

func (vr *VengefulRelay) AllowPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok {
		return fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.InternalChangePubKey(ctx, pubkey.Hex(), store.PubKeyAllowed, reason)
}

func (vr *VengefulRelay) InternalChangePubKey(ctx context.Context, pubkey string, state store.PubKeyState, reason string) error {
	return vr.Store.ChangePubKeyState(ctx, pubkey, state, reason)
}

func (vr *VengefulRelay) BanPubKey(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok {
		return fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.InternalChangePubKey(ctx, pubkey.Hex(), store.PubKeyBanned, reason)
}

func (vr *VengefulRelay) MakeAdmin(ctx context.Context, pubkey nostr.PubKey, reason string) error {
	key, ok := khatru.GetAuthed(ctx)
	if !ok {
		return fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return fmt.Errorf("Not authorized")
	}
	return vr.InternalChangePubKey(ctx, pubkey.Hex(), store.PubKeyAdmin, reason)
}

func (vr *VengefulRelay) ListAllowedPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok {
		return nil, fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return nil, fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	return vr.InternalListPubKeys(store.PubKeyAllowed)
}

func (vr *VengefulRelay) ListAdminPubKeys(ctx context.Context) ([]nip86.PubKeyReason, error) {
	key, ok := khatru.GetAuthed(ctx)
	if !ok {
		return nil, fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return nil, fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	return vr.InternalListPubKeys(store.PubKeyAdmin)
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
	if !ok {
		return nil, fmt.Errorf("Not authorized")
	}
	admins, _, err := vr.Store.QueryAllPubkeyStates(store.PubKeyAdmin)
	if err != nil {
		return nil, fmt.Errorf("Internal server error")
	}
	if !slices.Contains(admins, key) || key != *vr.Info.PubKey {
		return nil, fmt.Errorf("Not authorized")
	}
	return vr.InternalListPubKeys(store.PubKeyBanned)
}
