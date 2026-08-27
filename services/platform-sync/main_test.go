package main

import "testing"

func TestParseOptionsHonorsEnvironment(t *testing.T) {
	env := map[string]string{
		"CONTRACT_PATH":         "/opt/platform-sync/contract/platform-input-contract.yaml",
		"SYNC_DRY_RUN":          "true",
		"SYNC_LOCK_TTL_SECONDS": "900",
		"SYNC_NAMESPACE":        "prod-ssl-proxy",
	}
	configured, err := parseOptions(nil, func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	if !configured.dryRun || configured.lockTTL != 900 || configured.contractPath != env["CONTRACT_PATH"] {
		t.Fatalf("environment was not honored: %#v", configured)
	}
}

func TestParseOptionsFlagsOverrideEnvironment(t *testing.T) {
	configured, err := parseOptions([]string{"--dry-run=false", "--lock-ttl=30", "--contract=/tmp/contract.yaml"}, func(name string) string {
		if name == "SYNC_DRY_RUN" {
			return "true"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if configured.dryRun || configured.lockTTL != 30 || configured.contractPath != "/tmp/contract.yaml" {
		t.Fatalf("flags did not override environment: %#v", configured)
	}
}

func TestParseOptionsRejectsInvalidEnvironment(t *testing.T) {
	if _, err := parseOptions(nil, func(name string) string {
		if name == "SYNC_LOCK_TTL_SECONDS" {
			return "600s"
		}
		return ""
	}); err == nil {
		t.Fatal("invalid lock TTL was accepted")
	}
}
