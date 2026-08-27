package validate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func validateTLS(c *contract.Contract, data map[string]map[string][]byte) error {
	tlsInput, ok := data[c.Validation.IdentityCertificate.SecretName]
	if !ok {
		return fmt.Errorf("TLS secret %s not found", c.Validation.IdentityCertificate.SecretName)
	}

	caCert, ok := tlsInput["ca.crt"]
	if !ok {
		return fmt.Errorf("TLS secret missing ca.crt")
	}

	tlsCert, ok := tlsInput["tls.crt"]
	if !ok {
		return fmt.Errorf("TLS secret missing tls.crt")
	}

	tlsKey, ok := tlsInput["tls.key"]
	if !ok {
		return fmt.Errorf("TLS secret missing tls.key")
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	certBlock, _ := pem.Decode(tlsCert)
	if certBlock == nil {
		return fmt.Errorf("failed to decode TLS certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse TLS certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(tlsKey)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode TLS key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse TLS key: %w", err)
			}
		}
	}
	_ = key

	dnsName := c.Validation.IdentityCertificate.DNSName
	found := false
	for _, name := range cert.DNSNames {
		if name == dnsName {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("certificate does not contain DNS name %s", dnsName)
	}

	opts := x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}
