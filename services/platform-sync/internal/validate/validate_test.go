package validate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

func TestValidateTLSVerifiesPrivateKey(t *testing.T) {
	certificate := testCertificate(t, "gateway.rclabs.uk")
	c := &contract.Contract{Validation: contract.Validation{IdentityCertificate: contract.IdentityCertificateValidation{
		SecretName: "identity", DNSName: "gateway.rclabs.uk",
	}}}
	valid := map[string]map[string][]byte{"identity": {
		"ca.crt": certificate.ca, "tls.crt": certificate.certificate, "tls.key": certificate.privateKey,
	}}
	if err := validateTLS(c, valid); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	other := testCertificate(t, "gateway.rclabs.uk")
	valid["identity"]["tls.key"] = other.privateKey
	if err := validateTLS(c, valid); err == nil {
		t.Fatal("certificate with a different private key was accepted")
	}
}

func TestValidateLokiComparesDeclaredHash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	c := &contract.Contract{Validation: contract.Validation{LokiHtpasswd: contract.LokiHtpasswdValidation{
		SecretName: "observability", UsernameKey: "username", PasswordKey: "password", HtpasswdKey: "htpasswd",
	}}}
	data := map[string]map[string][]byte{"observability": {
		"username": []byte("loki"), "password": []byte("correct"), "htpasswd": []byte("loki:" + string(hash)),
	}}
	if err := validateLoki(c, data); err != nil {
		t.Fatalf("valid htpasswd rejected: %v", err)
	}
	data["observability"]["password"] = []byte("wrong")
	if err := validateLoki(c, data); err == nil {
		t.Fatal("mismatched htpasswd password was accepted")
	}
}

func TestValidatePostgresRejectsStaticContractMismatchesBeforeConnecting(t *testing.T) {
	c := postgresContract()
	data := postgresStaticData()
	data["endpoint"]["POSTGRES_DATABASE"] = []byte("wrong")
	if err := validatePostgres(context.Background(), c, data); err == nil {
		t.Fatal("wrong database was accepted")
	}
	data = postgresStaticData()
	data["endpoint"]["POSTGRES_SSL_MODE"] = []byte("require")
	if err := validatePostgres(context.Background(), c, data); err == nil {
		t.Fatal("non-verify-full transport was accepted")
	}
	data = postgresStaticData()
	data["postgres-tls"]["ca.crt"] = []byte("not a certificate")
	if err := validatePostgres(context.Background(), c, data); err == nil {
		t.Fatal("invalid PostgreSQL CA was accepted")
	}
}

func TestValidatePgBouncerRequiresRuntimeAccounts(t *testing.T) {
	c := postgresContract()
	data := pgbouncerTLSData(t, "postgres-pgbouncer")
	data["pgbouncer-runtime-users"] = map[string][]byte{
		"userlist.txt": []byte(`"atheros_search_runtime" "secret"
"octopus_runtime" "secret"`),
	}
	if err := validatePgBouncer(c, data); err == nil {
		t.Fatal("userlist missing schema_migrator_runtime was accepted")
	}
	data["pgbouncer-runtime-users"]["userlist.txt"] = []byte(`"atheros_search_runtime" "secret"
"octopus_runtime" "secret"
"schema_migrator_runtime" "secret"`)
	if err := validatePgBouncer(c, data); err != nil {
		t.Fatalf("complete userlist rejected: %v", err)
	}
}

func TestValidatePgBouncerListenerTLS(t *testing.T) {
	c := postgresContract()
	t.Run("accepts a valid listener certificate", func(t *testing.T) {
		if err := validatePgBouncer(c, pgbouncerTLSData(t, "postgres-pgbouncer")); err != nil {
			t.Fatalf("valid listener TLS was rejected: %v", err)
		}
	})
	t.Run("rejects missing keys", func(t *testing.T) {
		data := pgbouncerTLSData(t, "postgres-pgbouncer")
		delete(data["pgbouncer-listener-tls"], "tls.key")
		if err := validatePgBouncer(c, data); err == nil {
			t.Fatal("listener TLS without a private key was accepted")
		}
	})
	t.Run("rejects a mismatched key", func(t *testing.T) {
		data := pgbouncerTLSData(t, "postgres-pgbouncer")
		data["pgbouncer-listener-tls"]["tls.key"] = testCertificate(t, "postgres-pgbouncer").privateKey
		if err := validatePgBouncer(c, data); err == nil {
			t.Fatal("listener TLS with a mismatched key was accepted")
		}
	})
	t.Run("rejects an untrusted chain", func(t *testing.T) {
		trusted := pgbouncerTLSData(t, "postgres-pgbouncer")
		untrusted := testCertificate(t, "postgres-pgbouncer")
		trusted["pgbouncer-listener-tls"]["tls.crt"] = untrusted.certificate
		trusted["pgbouncer-listener-tls"]["tls.key"] = untrusted.privateKey
		if err := validatePgBouncer(c, trusted); err == nil {
			t.Fatal("listener TLS with an untrusted chain was accepted")
		}
	})
	t.Run("rejects the wrong DNS SAN", func(t *testing.T) {
		if err := validatePgBouncer(c, pgbouncerTLSData(t, "other.service")); err == nil {
			t.Fatal("listener TLS with the wrong DNS SAN was accepted")
		}
	})
}

func TestValidateWireGuardRequiresRealMatchingKeys(t *testing.T) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	key := func(raw []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(raw)) }
	data := map[string]map[string][]byte{"wireguard-config": {
		"server.conf": []byte("[Interface]\nPrivateKey = value\n"), "Corefile": []byte(".:53 {}"),
		"privatekey-server": key(private), "publickey-server": key(public),
		"peer1.conf": []byte("[Interface]\n[Peer]\n"), "peer1-obfuscated.conf": []byte("configured"),
		"publickey-peer1": key(public), "presharedkey-peer1": key(private),
		"peer2.conf": []byte("[Interface]\n[Peer]\n"), "peer2-obfuscated.conf": []byte("configured"),
		"publickey-peer2": key(public), "presharedkey-peer2": key(private),
	}}
	if err := validateWireGuard(&contract.Contract{}, data); err != nil {
		t.Fatalf("valid WireGuard data rejected: %v", err)
	}
	data["wireguard-config"]["publickey-server"] = []byte("arbitrary")
	if err := validateWireGuard(&contract.Contract{}, data); err == nil {
		t.Fatal("arbitrary WireGuard key was accepted")
	}
}

type certificateFixture struct {
	ca          []byte
	certificate []byte
	privateKey  []byte
}

func testCertificate(t *testing.T, dnsName string) certificateFixture {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFixture{
		ca:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		privateKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}),
	}
}

func postgresContract() *contract.Contract {
	return &contract.Contract{Validation: contract.Validation{Postgres: contract.PostgresValidation{
		EndpointConfigMapName: "endpoint", Database: "sync", Transport: "tls-verify-full",
		TLSSecretName: "postgres-tls", GrantMatrixDocument: "sql/postgres",
		PgBouncerListenerTLSSecretName: "pgbouncer-listener-tls", PgBouncerListenerTLSServerName: "postgres-pgbouncer",
		Host: "192.168.1.242", Port: 4000, TLSServerName: "192.168.1.242",
		Accounts: map[string]string{
			"postgres-atheros-search": "atheros_search_runtime", "postgres-keycloak": "keycloak_runtime",
			"postgres-octopus": "octopus_runtime", "postgres-schema-migrator": "schema_migrator_runtime",
			"postgres-schema-owner": "schema_owner",
		},
	}}}
}

func pgbouncerTLSData(t *testing.T, dnsName string) map[string]map[string][]byte {
	t.Helper()
	listener := testCertificate(t, dnsName)
	return map[string]map[string][]byte{
		"pgbouncer-listener-tls": {
			"ca.crt": listener.ca, "tls.crt": listener.certificate, "tls.key": listener.privateKey,
		},
		"pgbouncer-runtime-users": {
			"userlist.txt": []byte(`"atheros_search_runtime" "secret"
"octopus_runtime" "secret"
"schema_migrator_runtime" "secret"`),
		},
	}
}

func postgresStaticData() map[string]map[string][]byte {
	ca := testCertificateForCA()
	data := map[string]map[string][]byte{
		"endpoint": {
			"POSTGRES_HOST": []byte("192.168.1.242"), "POSTGRES_PORT": []byte("4000"),
			"POSTGRES_DATABASE": []byte("sync"), "POSTGRES_SSL_MODE": []byte("verify-full"),
			"POSTGRES_SSL_SERVER_NAME": []byte("192.168.1.242"),
		},
		"postgres-tls": {"ca.crt": ca},
	}
	for secret := range canonicalAccounts {
		data[secret] = map[string][]byte{"password": []byte("secret")}
	}
	return data
}

func testCertificateForCA() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "PostgreSQL CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
