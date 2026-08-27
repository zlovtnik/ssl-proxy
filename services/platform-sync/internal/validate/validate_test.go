package validate

import (
	"testing"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func TestValidateTLS(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]map[string][]byte
		wantErr bool
	}{
		{
			name: "missing TLS secret",
			data: map[string]map[string][]byte{},
			wantErr: true,
		},
		{
			name: "missing ca.crt",
			data: map[string]map[string][]byte{
				"ssl-proxy-identity-tls": {},
			},
			wantErr: true,
		},
		{
			name: "missing tls.crt",
			data: map[string]map[string][]byte{
				"ssl-proxy-identity-tls": {
					"ca.crt": []byte("test"),
				},
			},
			wantErr: true,
		},
		{
			name: "missing tls.key",
			data: map[string]map[string][]byte{
				"ssl-proxy-identity-tls": {
					"ca.crt":  []byte("test"),
					"tls.crt": []byte("test"),
				},
			},
			wantErr: true,
		},
	}

	c := &contract.Contract{
		Validation: contract.Validation{
			IdentityCertificate: struct {
				SecretName string `yaml:"secretName"`
				DNSName    string `yaml:"dnsName"`
			}{
				SecretName: "ssl-proxy-identity-tls",
				DNSName:    "gateway.rclabs.uk",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTLS(c, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePostgres(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]map[string][]byte
		wantErr bool
	}{
		{
			name: "missing endpoint ConfigMap",
			data: map[string]map[string][]byte{},
			wantErr: true,
		},
		{
			name: "missing POSTGRES_HOST",
			data: map[string]map[string][]byte{
				"ssl-proxy-prod-postgres-endpoint": {},
			},
			wantErr: true,
		},
	}

	c := &contract.Contract{
		Validation: contract.Validation{
			Postgres: struct {
				EndpointConfigMapName string            `yaml:"endpointConfigMapName"`
				Database              string            `yaml:"database"`
				Transport             string            `yaml:"transport"`
				TLSSecretName         string            `yaml:"tlsSecretName"`
				GrantMatrixDocument   string            `yaml:"grantMatrixDocument"`
				Accounts              map[string]string `yaml:"accounts"`
			}{
				EndpointConfigMapName: "ssl-proxy-prod-postgres-endpoint",
				Database:              "sync",
				Transport:             "tls-verify-full",
				TLSSecretName:         "postgres-runtime-tls",
				Accounts:              map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePostgres(c, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePostgres() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePgBouncer(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]map[string][]byte
		wantErr bool
	}{
		{
			name: "missing PgBouncer secret",
			data: map[string]map[string][]byte{},
			wantErr: true,
		},
		{
			name: "missing userlist.txt",
			data: map[string]map[string][]byte{
				"pgbouncer-runtime-users": {},
			},
			wantErr: true,
		},
		{
			name: "valid userlist",
			data: map[string]map[string][]byte{
				"pgbouncer-runtime-users": {
					"userlist.txt": []byte(`"user1" "password1"
"user2" "password2"`),
				},
			},
			wantErr: false,
		},
		{
			name: "invalid userlist format",
			data: map[string]map[string][]byte{
				"pgbouncer-runtime-users": {
					"userlist.txt": []byte("invalid"),
				},
			},
			wantErr: true,
		},
	}

	c := &contract.Contract{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePgBouncer(c, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePgBouncer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateWireGuard(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]map[string][]byte
		wantErr bool
	}{
		{
			name: "missing WireGuard config",
			data: map[string]map[string][]byte{},
			wantErr: true,
		},
		{
			name: "missing server.conf",
			data: map[string]map[string][]byte{
				"wireguard-config": {},
			},
			wantErr: true,
		},
		{
			name: "valid WireGuard config",
			data: map[string]map[string][]byte{
				"wireguard-config": {
					"server.conf":           []byte("[Interface]\nPrivateKey = test\n"),
					"Corefile":              []byte("test"),
					"privatekey-server":     []byte("testkey"),
					"publickey-server":      []byte("testkey"),
					"peer1.conf":            []byte("test"),
					"peer1-obfuscated.conf": []byte("test"),
					"publickey-peer1":       []byte("testkey"),
					"presharedkey-peer1":    []byte("testkey"),
					"peer2.conf":            []byte("test"),
					"peer2-obfuscated.conf": []byte("test"),
					"publickey-peer2":       []byte("testkey"),
					"presharedkey-peer2":    []byte("testkey"),
				},
			},
			wantErr: false,
		},
	}

	c := &contract.Contract{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWireGuard(c, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateWireGuard() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
