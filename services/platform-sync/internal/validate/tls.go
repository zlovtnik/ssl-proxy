package validate

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func validateTLS(c *contract.Contract, data map[string]map[string][]byte) error {
	name := c.Validation.IdentityCertificate.SecretName
	tlsInput, ok := data[name]
	if !ok {
		return fmt.Errorf("TLS secret %s not found", name)
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

	caPool, err := parseCAPool(caCert)
	if err != nil {
		return fmt.Errorf("parse identity CA: %w", err)
	}
	pair, err := tls.X509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("certificate/private key mismatch or parse failure: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return fmt.Errorf("parse intermediate certificate: %w", parseErr)
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         caPool,
		Intermediates: intermediates,
		DNSName:       c.Validation.IdentityCertificate.DNSName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("certificate chain or DNS verification failed: %w", err)
	}
	return nil
}

func parseCAPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := data
	count := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(certificate)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return pool, nil
}
