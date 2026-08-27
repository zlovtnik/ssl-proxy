package validate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"golang.org/x/crypto/curve25519"
)

func validateWireGuard(_ *contract.Contract, data map[string]map[string][]byte) error {
	config, ok := data["wireguard-config"]
	if !ok {
		return fmt.Errorf("WireGuard config secret not found")
	}
	requiredFiles := []string{
		"server.conf", "Corefile", "privatekey-server", "publickey-server",
		"peer1.conf", "peer1-obfuscated.conf", "publickey-peer1", "presharedkey-peer1",
		"peer2.conf", "peer2-obfuscated.conf", "publickey-peer2", "presharedkey-peer2",
	}
	for _, key := range requiredFiles {
		if len(config[key]) == 0 {
			return fmt.Errorf("WireGuard config missing non-empty key %s", key)
		}
	}

	serverConfig := string(config["server.conf"])
	if !strings.Contains(serverConfig, "[Interface]") || !strings.Contains(serverConfig, "PrivateKey") {
		return fmt.Errorf("WireGuard server.conf must contain an interface and private key")
	}
	for _, name := range []string{"peer1.conf", "peer2.conf"} {
		peerConfig := string(config[name])
		if !strings.Contains(peerConfig, "[Interface]") || !strings.Contains(peerConfig, "[Peer]") {
			return fmt.Errorf("WireGuard %s must contain Interface and Peer sections", name)
		}
	}

	decoded := make(map[string][]byte)
	for _, key := range []string{"privatekey-server", "publickey-server", "publickey-peer1", "presharedkey-peer1", "publickey-peer2", "presharedkey-peer2"} {
		value := strings.TrimSpace(string(config[key]))
		if strings.ContainsAny(value, "\n\r") {
			return fmt.Errorf("WireGuard key %s contains unexpected newlines", key)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) != curve25519.ScalarSize {
			return fmt.Errorf("WireGuard key %s must be canonical base64 encoding of 32 bytes", key)
		}
		decoded[key] = raw
	}
	serverPublic, err := curve25519.X25519(decoded["privatekey-server"], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive WireGuard server public key: %w", err)
	}
	if !bytes.Equal(serverPublic, decoded["publickey-server"]) {
		return fmt.Errorf("WireGuard server public key does not match private key")
	}
	return nil
}
