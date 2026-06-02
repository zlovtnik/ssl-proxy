package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

type TokenAuth struct {
	expectedDigest []byte
}

func NewTokenAuth(hexDigest string) (*TokenAuth, error) {
	hexDigest = strings.TrimSpace(strings.ToLower(hexDigest))
	if hexDigest == "" {
		return &TokenAuth{}, nil
	}
	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("token digest must decode to %d bytes, got %d", sha256.Size, len(digest))
	}
	return &TokenAuth{expectedDigest: digest}, nil
}

func (a *TokenAuth) Enabled() bool {
	return len(a.expectedDigest) > 0
}

func (a *TokenAuth) VerifyAuthorization(header string) bool {
	if !a.Enabled() {
		return true
	}
	const prefix = "bearer "
	header = strings.TrimSpace(header)
	if len(header) < len(prefix) || strings.ToLower(header[:len(prefix)]) != prefix {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], a.expectedDigest) == 1
}
