package contract

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "platform.ssl-proxy.io/v1alpha1"
	Kind       = "PlatformInputContract"
)

type Input struct {
	Kind      string   `yaml:"kind"`
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type,omitempty"`
	VaultPath string   `yaml:"vaultPath"`
	Keys      []string `yaml:"keys"`
}

type IdentityCertificateValidation struct {
	SecretName string `yaml:"secretName"`
	DNSName    string `yaml:"dnsName"`
}

type LokiHtpasswdValidation struct {
	SecretName  string `yaml:"secretName"`
	UsernameKey string `yaml:"usernameKey"`
	PasswordKey string `yaml:"passwordKey"`
	HtpasswdKey string `yaml:"htpasswdKey"`
}

type PostgresValidation struct {
	EndpointConfigMapName          string            `yaml:"endpointConfigMapName"`
	Database                       string            `yaml:"database"`
	Transport                      string            `yaml:"transport"`
	TLSSecretName                  string            `yaml:"tlsSecretName"`
	PgBouncerListenerTLSSecretName string            `yaml:"pgbouncerListenerTLSSecretName"`
	PgBouncerListenerTLSServerName string            `yaml:"pgbouncerListenerTLSServerName"`
	GrantMatrixDocument            string            `yaml:"grantMatrixDocument"`
	Accounts                       map[string]string `yaml:"accounts"`
	Host                           string            `yaml:"-"`
	Port                           int               `yaml:"-"`
	TLSServerName                  string            `yaml:"-"`
}

type Validation struct {
	IdentityCertificate IdentityCertificateValidation `yaml:"identityCertificate"`
	LokiHtpasswd        LokiHtpasswdValidation        `yaml:"lokiHtpasswd"`
	Postgres            PostgresValidation            `yaml:"postgres"`
}

type Contract struct {
	Environment string                 `yaml:"environment"`
	Namespace   string                 `yaml:"namespace"`
	Inputs      []Input                `yaml:"inputs"`
	Validation  Validation             `yaml:"validation"`
	Raw         map[string]interface{} `yaml:"-"`
}

func Load(path string) (*Contract, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator-selected contract path is the intended input.
	if err != nil {
		return nil, fmt.Errorf("read contract: %w", err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse contract: %w", err)
	}
	if getString(raw, "apiVersion") != APIVersion {
		return nil, fmt.Errorf("contract apiVersion must be %s", APIVersion)
	}
	if getString(raw, "kind") != Kind {
		return nil, fmt.Errorf("contract kind must be %s", Kind)
	}

	spec, ok := raw["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("contract missing spec")
	}

	inputsRaw, ok := spec["inputs"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("contract missing inputs")
	}

	var inputs []Input
	for i, raw := range inputsRaw {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("input %d is not a mapping", i)
		}
		input := Input{
			Kind:      getString(m, "kind"),
			Name:      getString(m, "name"),
			Type:      getString(m, "type"),
			VaultPath: getString(m, "vaultPath"),
		}
		if keys, ok := m["keys"].([]interface{}); ok {
			for _, k := range keys {
				if s, ok := k.(string); ok {
					input.Keys = append(input.Keys, s)
				}
			}
		}
		inputs = append(inputs, input)
	}

	validationRaw, _ := spec["validation"].(map[string]interface{})
	var v Validation
	if validationRaw != nil {
		if ic, ok := validationRaw["identityCertificate"].(map[string]interface{}); ok {
			v.IdentityCertificate.SecretName = getString(ic, "secretName")
			v.IdentityCertificate.DNSName = getString(ic, "dnsName")
		}
		if lh, ok := validationRaw["lokiHtpasswd"].(map[string]interface{}); ok {
			v.LokiHtpasswd.SecretName = getString(lh, "secretName")
			v.LokiHtpasswd.UsernameKey = getString(lh, "usernameKey")
			v.LokiHtpasswd.PasswordKey = getString(lh, "passwordKey")
			v.LokiHtpasswd.HtpasswdKey = getString(lh, "htpasswdKey")
		}
		if pg, ok := validationRaw["postgres"].(map[string]interface{}); ok {
			v.Postgres.EndpointConfigMapName = getString(pg, "endpointConfigMapName")
			v.Postgres.Database = getString(pg, "database")
			v.Postgres.Transport = getString(pg, "transport")
			v.Postgres.TLSSecretName = getString(pg, "tlsSecretName")
			v.Postgres.PgBouncerListenerTLSSecretName = getString(pg, "pgbouncerListenerTLSSecretName")
			v.Postgres.PgBouncerListenerTLSServerName = getString(pg, "pgbouncerListenerTLSServerName")
			v.Postgres.GrantMatrixDocument = getString(pg, "grantMatrixDocument")
			if accounts, ok := pg["accounts"].(map[string]interface{}); ok {
				v.Postgres.Accounts = make(map[string]string)
				for k, val := range accounts {
					if s, ok := val.(string); ok {
						v.Postgres.Accounts[k] = s
					}
				}
			}
		}
	}
	if bootstrap, ok := spec["bootstrap"].(map[string]interface{}); ok {
		if postgres, ok := bootstrap["postgres"].(map[string]interface{}); ok {
			if endpoint, ok := postgres["endpoint"].(map[string]interface{}); ok {
				v.Postgres.Host = getString(endpoint, "host")
				v.Postgres.Port = getInt(endpoint, "port")
				v.Postgres.TLSServerName = getString(endpoint, "tlsServerName")
			}
		}
	}

	c := &Contract{
		Environment: getString(spec, "environment"),
		Namespace:   getString(spec, "namespace"),
		Inputs:      inputs,
		Validation:  v,
		Raw:         raw,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate rejects ambiguous contracts before any external reads or writes occur.
func (c *Contract) Validate() error {
	if strings.TrimSpace(c.Environment) == "" {
		return fmt.Errorf("contract environment is required")
	}
	if strings.TrimSpace(c.Namespace) == "" {
		return fmt.Errorf("contract namespace is required")
	}
	if len(c.Inputs) == 0 {
		return fmt.Errorf("contract must declare at least one input")
	}

	identities := make(map[string]struct{}, len(c.Inputs))
	for i, input := range c.Inputs {
		if input.Kind != "Secret" && input.Kind != "ConfigMap" {
			return fmt.Errorf("input %d has unsupported kind %q", i, input.Kind)
		}
		if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.VaultPath) == "" {
			return fmt.Errorf("input %d requires name and vaultPath", i)
		}
		identity := input.Kind + "/" + input.Name
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("duplicate input %s", identity)
		}
		identities[identity] = struct{}{}
		if len(input.Keys) == 0 {
			return fmt.Errorf("input %s must declare at least one key", identity)
		}
		keys := make(map[string]struct{}, len(input.Keys))
		for _, key := range input.Keys {
			if strings.TrimSpace(key) == "" {
				return fmt.Errorf("input %s contains an empty key", identity)
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("input %s contains duplicate key %s", identity, key)
			}
			keys[key] = struct{}{}
		}
	}

	pg := c.Validation.Postgres
	if pg.EndpointConfigMapName == "" || pg.Database == "" || pg.Transport == "" ||
		pg.TLSSecretName == "" || pg.PgBouncerListenerTLSSecretName == "" ||
		pg.PgBouncerListenerTLSServerName == "" || pg.GrantMatrixDocument == "" || len(pg.Accounts) == 0 {
		return fmt.Errorf("contract PostgreSQL validation is incomplete")
	}
	if pg.Host == "" || pg.Port < 1 || pg.Port > 65535 || pg.TLSServerName == "" {
		return fmt.Errorf("contract PostgreSQL bootstrap endpoint is incomplete")
	}
	return nil
}

func (c *Contract) ByIdentity() map[string]Input {
	m := make(map[string]Input)
	for _, input := range c.Inputs {
		key := input.Kind + "/" + input.Name
		m[key] = input
	}
	return m
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	switch value := m[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case uint64:
		if value > uint64(^uint(0)>>1) {
			return 0
		}
		return int(value) // #nosec G115 -- guarded against platform int overflow above
	case float64:
		return int(value)
	case string:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}
