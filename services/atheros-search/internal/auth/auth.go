package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

type Decision int

const (
	DecisionUnauthorized Decision = iota
	DecisionForbidden
	DecisionAuthorized
)

type JWTConfig struct {
	Issuer   string
	JWKSURI  string
	Audience string
	ClientID string
}

type TokenAuth struct {
	expectedDigest []byte
	jwt            *jwtVerifier
}

type jwtVerifier struct {
	config JWTConfig
	client *http.Client
	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	expiry time.Time
	now    func() time.Time
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type jwtClaims struct {
	Issuer         string                    `json:"iss"`
	Audience       json.RawMessage           `json:"aud"`
	ExpiresAt      json.Number               `json:"exp"`
	NotBefore      json.Number               `json:"nbf"`
	ResourceAccess map[string]resourceAccess `json:"resource_access"`
}

type resourceAccess struct {
	Roles []string `json:"roles"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType  string `json:"kty"`
	Use      string `json:"use"`
	KeyID    string `json:"kid"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
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

func NewJWTTokenAuth(config JWTConfig) (*TokenAuth, error) {
	config.Issuer = strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	config.JWKSURI = strings.TrimSpace(config.JWKSURI)
	config.Audience = strings.TrimSpace(config.Audience)
	config.ClientID = strings.TrimSpace(config.ClientID)
	if config.Issuer == "" || config.JWKSURI == "" || config.Audience == "" || config.ClientID == "" {
		return nil, errors.New("JWT issuer, JWKS URI, audience and client ID are required")
	}
	return &TokenAuth{jwt: &jwtVerifier{
		config: config,
		client: &http.Client{Timeout: 5 * time.Second},
		keys:   make(map[string]*rsa.PublicKey),
		now:    time.Now,
	}}, nil
}

func (a *TokenAuth) Enabled() bool {
	return a != nil && (len(a.expectedDigest) > 0 || a.jwt != nil)
}

func (a *TokenAuth) VerifyAuthorization(header string) bool {
	return a.AuthorizeAuthorization(context.Background(), header, RoleViewer, RoleOperator, RoleAdmin) == DecisionAuthorized
}

func (a *TokenAuth) AuthorizeAuthorization(ctx context.Context, header string, allowedRoles ...string) Decision {
	if !a.Enabled() {
		return DecisionAuthorized
	}
	token, ok := bearerToken(header)
	if !ok {
		return DecisionUnauthorized
	}
	if len(a.expectedDigest) > 0 {
		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], a.expectedDigest) == 1 {
			return DecisionAuthorized
		}
		return DecisionUnauthorized
	}
	roles, err := a.jwt.verify(ctx, token)
	if err != nil {
		return DecisionUnauthorized
	}
	if len(allowedRoles) == 0 {
		return DecisionAuthorized
	}
	for _, allowed := range allowedRoles {
		if _, ok := roles[allowed]; ok {
			return DecisionAuthorized
		}
	}
	return DecisionForbidden
}

func bearerToken(header string) (string, bool) {
	const prefix = "bearer "
	header = strings.TrimSpace(header)
	if len(header) < len(prefix) || strings.ToLower(header[:len(prefix)]) != prefix {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

func (v *jwtVerifier) verify(ctx context.Context, raw string) (map[string]struct{}, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("JWT must contain three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid JWT header")
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, errors.New("JWT must use RS256 with a key ID")
	}
	key, err := v.key(ctx, header.KeyID, false)
	if err != nil {
		key, err = v.key(ctx, header.KeyID, true)
		if err != nil {
			return nil, err
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("invalid JWT signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT claims")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var claims jwtClaims
	if err := decoder.Decode(&claims); err != nil {
		return nil, errors.New("invalid JWT claims")
	}
	if strings.TrimRight(claims.Issuer, "/") != v.config.Issuer {
		return nil, errors.New("wrong JWT issuer")
	}
	expiry, err := numberTime(claims.ExpiresAt)
	if err != nil || !v.now().Before(expiry) {
		return nil, errors.New("expired JWT")
	}
	if claims.NotBefore != "" {
		notBefore, err := numberTime(claims.NotBefore)
		if err != nil || v.now().Before(notBefore) {
			return nil, errors.New("JWT is not active")
		}
	}
	if !audienceContains(claims.Audience, v.config.Audience) {
		return nil, errors.New("wrong JWT audience")
	}
	clientRoles, ok := claims.ResourceAccess[v.config.ClientID]
	if !ok {
		return map[string]struct{}{}, nil
	}
	roles := make(map[string]struct{}, len(clientRoles.Roles))
	for _, role := range clientRoles.Roles {
		roles[role] = struct{}{}
	}
	return roles, nil
}

func numberTime(value json.Number) (time.Time, error) {
	seconds, err := value.Int64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0), nil
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil {
		return false
	}
	for _, audience := range multiple {
		if audience == expected {
			return true
		}
	}
	return false
}

func (v *jwtVerifier) key(ctx context.Context, keyID string, force bool) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[keyID]
	fresh := v.now().Before(v.expiry)
	v.mu.RUnlock()
	if key != nil && fresh && !force {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key = v.keys[keyID]
	if key == nil {
		return nil, errors.New("JWT key ID is unknown")
	}
	return key, nil
}

func (v *jwtVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fetch JWKS: unexpected status %d", resp.StatusCode)
	}
	var document jwksDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&document); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, candidate := range document.Keys {
		if candidate.KeyType != "RSA" || candidate.KeyID == "" || (candidate.Use != "" && candidate.Use != "sig") {
			continue
		}
		key, err := rsaKey(candidate)
		if err == nil {
			keys[candidate.KeyID] = key
		}
	}
	if len(keys) == 0 {
		return errors.New("JWKS contains no usable RSA signing keys")
	}
	v.mu.Lock()
	v.keys = keys
	v.expiry = v.now().Add(5 * time.Minute)
	v.mu.Unlock()
	return nil
}

func rsaKey(value jwk) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(value.Modulus)
	if err != nil || len(modulus) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(value.Exponent)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 | int(b)
	}
	if exponent < 3 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}
