package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenAuthVerifiesBearerTokenBySHA256(t *testing.T) {
	sum := sha256.Sum256([]byte("secret-token"))
	auth, err := NewTokenAuth(hex.EncodeToString(sum[:]))
	require.NoError(t, err)

	require.True(t, auth.VerifyAuthorization("Bearer secret-token"))
	require.True(t, auth.VerifyAuthorization("bearer secret-token"))
	require.False(t, auth.VerifyAuthorization("Bearer wrong"))
	require.False(t, auth.VerifyAuthorization("secret-token"))
}

func TestTokenAuthDisabledWhenDigestEmpty(t *testing.T) {
	auth, err := NewTokenAuth("")
	require.NoError(t, err)
	require.True(t, auth.VerifyAuthorization(""))
}
