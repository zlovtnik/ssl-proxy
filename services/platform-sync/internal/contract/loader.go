package contract

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "platform.ssl-proxy.io/v1alpha1"
	Kind       = "PlatformInputContract"
)

type Input struct {
	Kind       string   `yaml:"kind"`
	Name       string   `yaml:"name"`
	Type       string   `yaml:"type,omitempty"`
	VaultPath  string   `yaml:"vaultPath"`
	Keys       []string `yaml:"keys"`
}

type Validation struct {
	IdentityCertificate struct {
		SecretName string `yaml:"secretName"`
		DNSName    string `yaml:"dnsName"`
	} `yaml:"identityCertificate"`
	LokiHtpasswd struct {
		SecretName string `yaml:"secretName"`
		UsernameKey string `yaml:"usernameKey"`
		PasswordKey string `yaml:"passwordKey"`
		HtpasswdKey string `yaml:"htpasswdKey"`
	} `yaml:"lokiHtpasswd"`
	Postgres struct {
		EndpointConfigMapName string            `yaml:"endpointConfigMapName"`
		Database              string            `yaml:"database"`
		Transport             string            `yaml:"transport"`
		TLSSecretName         string            `yaml:"tlsSecretName"`
		GrantMatrixDocument   string            `yaml:"grantMatrixDocument"`
		Accounts              map[string]string `yaml:"accounts"`
	} `yaml:"postgres"`
}

type Contract struct {
	Environment string  `yaml:"environment"`
	Namespace   string  `yaml:"namespace"`
	Inputs      []Input `yaml:"inputs"`
	Validation  Validation `yaml:"validation"`
	Raw         map[string]interface{} `yaml:"-"`
}

func Load(path string) (*Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read contract: %w", err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse contract: %w", err)
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

	return &Contract{
		Environment: getString(spec, "environment"),
		Namespace:   getString(spec, "namespace"),
		Inputs:      inputs,
		Validation:  v,
		Raw:         raw,
	}, nil
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
