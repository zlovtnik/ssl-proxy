//go:build integration

package validate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestMetricsAccountRejectsColumnWrites(t *testing.T) {
	dsn := os.Getenv("PLATFORM_SYNC_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("run tests/postgres_grants_test.py to provision ephemeral PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := admin.Close(context.Background()); err != nil {
			t.Errorf("close fixture admin connection: %v", err)
		}
	}()
	var database string
	if err := admin.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil || database != "metrics_grants" {
		t.Fatalf("integration test requires the isolated metrics_grants database: %v", err)
	}
	_, err = admin.Exec(ctx, `
		CREATE ROLE octopus_metrics LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
		  PASSWORD 'metrics-grant-fixture';
		CREATE SCHEMA octopus_core;
		CREATE TABLE octopus_core.ingestion_evidence (first_seen_at timestamptz, message_key text);
		CREATE TABLE octopus_core.schema_readiness (
		  domain text, ready boolean, required_version text, applied_version text,
		  required_checksum text, applied_checksum text);
		INSERT INTO octopus_core.ingestion_evidence VALUES (CURRENT_TIMESTAMP, 'fixture');
		INSERT INTO octopus_core.schema_readiness VALUES ('octopus_core', true, '1', '1', 'fixture', 'fixture');`)
	if err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(filepath.Dir(canonicalGrantFixture(t, "octopus_core")), "metrics_read_only.sql.tmpl")
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, strings.ReplaceAll(string(fixture), "{{OCTOPUS_METRICS_ACCOUNT}}", "octopus_metrics")); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User, config.Password = "octopus_metrics", "metrics-grant-fixture"
	metrics, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := metrics.Close(context.Background()); err != nil {
			t.Errorf("close fixture metrics connection: %v", err)
		}
	}()
	assertReadOnly := func(t *testing.T) {
		t.Helper()
		if err := validateAccountGrants(ctx, metrics, "octopus_metrics"); err != nil {
			t.Fatalf("canonical read-only grants rejected: %v", err)
		}
	}
	assertReadOnly(t)
	if _, err := metrics.Exec(ctx, `SELECT first_seen_at FROM octopus_core.ingestion_evidence;
		SELECT domain, ready, required_version, applied_version, required_checksum, applied_checksum
		FROM octopus_core.schema_readiness`); err != nil {
		t.Fatalf("canonical metrics reads failed: %v", err)
	}
	for _, table := range []struct{ name, column string }{
		{"octopus_core.ingestion_evidence", "first_seen_at"},
		{"octopus_core.schema_readiness", "ready"},
	} {
		for _, privilege := range []string{"INSERT", "UPDATE"} {
			for _, recipient := range []string{"octopus_metrics", "PUBLIC"} {
				t.Run(table.name+"/"+privilege+"/"+recipient, func(t *testing.T) {
					// Identifiers and privileges are fixed fixture values.
					grant := fmt.Sprintf("GRANT %s (%s) ON %s TO %s", privilege, table.column, table.name, recipient)
					if _, err := admin.Exec(ctx, grant); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						revoke := fmt.Sprintf("REVOKE %s (%s) ON %s FROM %s", privilege, table.column, table.name, recipient)
						if _, err := admin.Exec(ctx, revoke); err != nil {
							t.Fatal(err)
						}
						assertReadOnly(t)
					})
					var tableWrite, columnWrite bool
					err := metrics.QueryRow(ctx, `SELECT
					  has_table_privilege(current_user, $1, 'INSERT,UPDATE,DELETE,TRUNCATE'),
					  has_any_column_privilege(current_user, $1, 'INSERT,UPDATE')`, table.name).Scan(&tableWrite, &columnWrite)
					if err != nil || tableWrite || !columnWrite {
						t.Fatalf("fixture must have column-only write access: table=%v column=%v err=%v", tableWrite, columnWrite, err)
					}
					if err := validateAccountGrants(ctx, metrics, "octopus_metrics"); err == nil {
						t.Fatal("accepted a metrics role with effective column write privileges")
					}
				})
			}
		}
	}
	for _, table := range []struct{ name, column string }{
		{"octopus_core.ingestion_evidence", "first_seen_at"},
		{"octopus_core.schema_readiness", "ready"},
	} {
		t.Run(table.name+"/owner", func(t *testing.T) {
			if _, err := admin.Exec(ctx, fmt.Sprintf("ALTER TABLE %s OWNER TO octopus_metrics; REVOKE ALL ON %s FROM octopus_metrics", table.name, table.name)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := admin.Exec(ctx, fmt.Sprintf("ALTER TABLE %s OWNER TO fixture; REVOKE UPDATE (%s) ON %s FROM octopus_metrics", table.name, table.column, table.name)); err != nil {
					t.Fatal(err)
				}
				assertReadOnly(t)
			})
			var writable bool
			if err := metrics.QueryRow(ctx, "SELECT has_any_column_privilege(current_user, $1, 'INSERT,UPDATE')", table.name).Scan(&writable); err != nil || writable {
				t.Fatalf("owner fixture must start without effective write privileges: %v", err)
			}
			if err := validateAccountGrants(ctx, metrics, "octopus_metrics"); err == nil {
				t.Error("accepted an owner that can restore its own write privileges")
			}
			if _, err := metrics.Exec(ctx, fmt.Sprintf("GRANT UPDATE (%s) ON %s TO octopus_metrics", table.column, table.name)); err != nil {
				t.Fatalf("owner fixture cannot restore its own write privilege: %v", err)
			}
		})
	}
}
