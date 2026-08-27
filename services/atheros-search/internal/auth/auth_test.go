package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestJWTAuthValidatesClaimsSignatureAndRoles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyID := "key-1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "kid": keyID,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer server.Close()

	issuer := "https://gateway.example.test/realms/middleware"
	authenticator, err := NewJWTTokenAuth(JWTConfig{
		Issuer: issuer, JWKSURI: server.URL, Audience: "atheros-search-ui", ClientID: "atheros-search-ui",
	})
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	authenticator.jwt.now = func() time.Time { return now }

	claims := func(role string) map[string]any {
		return map[string]any{
			"iss":             issuer,
			"aud":             []string{"account", "atheros-search-ui"},
			"exp":             now.Add(time.Minute).Unix(),
			"resource_access": map[string]any{"atheros-search-ui": map[string]any{"roles": []string{role}}},
		}
	}
	token := signedJWT(t, key, keyID, claims(RoleViewer))
	require.Equal(t, DecisionAuthorized, authenticator.AuthorizeAuthorization(context.Background(), "Bearer "+token, RoleViewer, RoleOperator, RoleAdmin))
	require.Equal(t, DecisionForbidden, authenticator.AuthorizeAuthorization(context.Background(), "Bearer "+token, RoleOperator, RoleAdmin))

	operator := signedJWT(t, key, keyID, claims(RoleOperator))
	require.Equal(t, DecisionAuthorized, authenticator.AuthorizeAuthorization(context.Background(), "Bearer "+operator, RoleOperator, RoleAdmin))
	admin := signedJWT(t, key, keyID, claims(RoleAdmin))
	require.Equal(t, DecisionAuthorized, authenticator.AuthorizeAuthorization(context.Background(), "Bearer "+admin, RoleOperator, RoleAdmin))

	tests := []struct {
		name   string
		key    *rsa.PrivateKey
		keyID  string
		mutate func(map[string]any)
	}{
		{name: "expired", key: key, keyID: keyID, mutate: func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }},
		{name: "wrong issuer", key: key, keyID: keyID, mutate: func(c map[string]any) { c["iss"] = "https://issuer.example.test" }},
		{name: "wrong audience", key: key, keyID: keyID, mutate: func(c map[string]any) { c["aud"] = []string{"account"} }},
		{name: "invalid signature", key: otherKey, keyID: keyID, mutate: func(map[string]any) {}},
		{name: "unknown key", key: otherKey, keyID: "unknown", mutate: func(map[string]any) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := claims(RoleViewer)
			test.mutate(value)
			badToken := signedJWT(t, test.key, test.keyID, value)
			require.Equal(t, DecisionUnauthorized, authenticator.AuthorizeAuthorization(context.Background(), "Bearer "+badToken, RoleViewer))
		})
	}
	require.Equal(t, DecisionUnauthorized, authenticator.AuthorizeAuthorization(context.Background(), "", RoleViewer))
}

func signedJWT(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestTokenAuthDisabledWhenDigestEmpty(t *testing.T) {
	auth, err := NewTokenAuth("")
	require.NoError(t, err)
	require.True(t, auth.VerifyAuthorization(""))
}

func TestTokenAuthRejectsWrongDigestLength(t *testing.T) {
	_, err := NewTokenAuth("deadbeef")
	require.ErrorContains(t, err, "token digest must decode to 32 bytes")
}
