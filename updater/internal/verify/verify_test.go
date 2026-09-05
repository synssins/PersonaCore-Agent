package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestVerify_ValidAndTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"version":"1.2.3"}`)
	sig := ed25519.Sign(priv, msg)

	if !Verify(pub, msg, sig) {
		t.Fatal("valid sig failed to verify")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if Verify(pub, tampered, sig) {
		t.Fatal("tampered message verified true")
	}

	badSig := append([]byte(nil), sig...)
	badSig[10] ^= 0x01
	if Verify(pub, msg, badSig) {
		t.Fatal("tampered sig verified true")
	}
}

func TestVerify_BadInputsReturnFalseNoPanic(t *testing.T) {
	if Verify(nil, nil, nil) {
		t.Fatal("nil should not verify")
	}
	if Verify(make([]byte, 5), []byte("x"), make([]byte, 64)) {
		t.Fatal("short pubkey should not verify")
	}
	if Verify(make([]byte, ed25519.PublicKeySize), []byte("x"), make([]byte, 10)) {
		t.Fatal("short sig should not verify")
	}
}

func TestDecodeKeyHex(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(pub)
	got, err := DecodeKeyHex(h)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("decoded key mismatch")
	}

	if _, err := DecodeKeyHex("zznothex"); err == nil {
		t.Fatal("expected hex error")
	}
	if _, err := DecodeKeyHex("aabb"); err == nil {
		t.Fatal("expected length error")
	}
}
