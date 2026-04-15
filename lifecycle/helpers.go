/*
Package lifecycle — helpers.go provides shared utilities for the lifecycle
package. Internal helpers, not exported.
*/
package lifecycle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dustinxie/ecc"
)

// ecdsaPubKey is the ecdsa.PublicKey type alias for package-internal use.
type ecdsaPubKey = ecdsa.PublicKey

func secp256k1() elliptic.Curve { return ecc.P256k1() }

// parseSecp256k1PubKey parses a 65-byte uncompressed secp256k1 public key.
func parseSecp256k1PubKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, errors.New("lifecycle: empty public key bytes")
	}
	c := secp256k1()
	x, y := elliptic.Unmarshal(c, data)
	if x == nil {
		return nil, fmt.Errorf("lifecycle: invalid secp256k1 public key (%d bytes)", len(data))
	}
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
}

// mustMarshalJSON marshals v to JSON, panicking on error.
// Only used for constructing well-known payload structures where
// marshaling cannot fail (map[string]any with primitive values).
func mustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("lifecycle: marshal JSON: %v", err))
	}
	return b
}
