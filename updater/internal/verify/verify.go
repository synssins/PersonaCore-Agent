// Package verify wraps crypto/ed25519 for the updater.
//
// The public key is baked into the binary at build time via
//
//	-ldflags "-X main.PublicKeyHex=<hex>"
//
// and passed here as a byte slice, so this package holds no globals.
package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// DecodeKeyHex parses a hex-encoded Ed25519 public key.
func DecodeKeyHex(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pubkey hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// Verify returns true iff sig is a valid Ed25519 signature of message
// under pubkey. Never panics on bad input — returns false.
func Verify(pubkey ed25519.PublicKey, message, sig []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubkey, message, sig)
}
