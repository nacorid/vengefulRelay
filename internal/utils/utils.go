package utils

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Decode bech32 public key with 'npub' human-readable part into hex encoded public key
func DecodeNpub(npub string) (string, error) {
	hrp, byt, err := bech32.DecodeNoLimit(npub)
	if err != nil {
		return hrp, err
	}
	grp, err := bech32.ConvertBits(byt, 5, 8, false)
	if err != nil {
		return hrp, err
	}
	if len(grp) < 32 {
		return hrp, fmt.Errorf("invalid npub")
	}
	return hex.EncodeToString(grp[0:32]), nil
}
