package relay

import (
	"context"

	"fiatjaf.com/nostr"
)

func (vr *VengefulRelay) afterEventStored(ctx context.Context, evt nostr.Event) {
	if evt.Kind == 62 {
		vr.handleNIP62(ctx, evt)
	}
}

func (vr *VengefulRelay) handleNIP62(ctx context.Context, evt nostr.Event) {
	vr.logger.InfoContext(ctx, "NIP-62 Vanish event processed, deleting events from pubkey", "pubkey", evt.PubKey.Hex())

	go func() {
		err := vr.Store.VanishPubKey(ctx, evt.PubKey.Hex())
		if err != nil {
			vr.logger.ErrorContext(ctx, "failed to delete events for NIP-62 Vanish request", "pubkey", evt.PubKey.Hex(), "error", err)
		}
	}()
}
