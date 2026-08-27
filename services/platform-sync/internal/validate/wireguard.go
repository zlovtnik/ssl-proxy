package validate

import (
	"fmt"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func validateWireGuard(c *contract.Contract, data map[string]map[string][]byte) error {
	wgData, ok := data["wireguard-config"]
	if !ok {
		return fmt.Errorf("WireGuard config secret not found")
	}

	requiredKeys := []string{
		"server.conf", "Corefile",
		"privatekey-server", "publickey-server",
		"peer1.conf", "peer1-obfuscated.conf",
		"publickey-peer1", "presharedkey-peer1",
		"peer2.conf", "peer2-obfuscated.conf",
		"publickey-peer2", "presharedkey-peer2",
	}

	for _, key := range requiredKeys {
		if _, ok := wgData[key]; !ok {
			return fmt.Errorf("WireGuard config missing key %s", key)
		}
	}

	serverConf := string(wgData["server.conf"])
	if !strings.Contains(serverConf, "[Interface]") {
		return fmt.Errorf("WireGuard server.conf missing [Interface] section")
	}

	if !strings.Contains(serverConf, "PrivateKey") {
		return fmt.Errorf("WireGuard server.conf missing PrivateKey")
	}

	for _, key := range []string{"privatekey-server", "publickey-server", "publickey-peer1", "presharedkey-peer1", "publickey-peer2", "presharedkey-peer2"} {
		value := string(wgData[key])
		if len(value) == 0 {
			return fmt.Errorf("WireGuard key %s is empty", key)
		}
		if strings.ContainsAny(value, "\n\r") {
			return fmt.Errorf("WireGuard key %s contains unexpected newlines", key)
		}
	}

	return nil
}
