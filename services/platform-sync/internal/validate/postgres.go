package validate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

var canonicalAccounts = map[string]string{
	"postgres-atheros-search":  "atheros_search_runtime",
	"postgres-keycloak":        "keycloak_runtime",
	"postgres-octopus":         "octopus_runtime",
	"postgres-schema-migrator": "schema_migrator_runtime",
	"postgres-schema-owner":    "schema_owner",
}

type tableGrant struct {
	table      string
	privileges []string
}

func validatePostgres(ctx context.Context, c *contract.Contract, data map[string]map[string][]byte) error {
	pg := c.Validation.Postgres
	endpoint, ok := data[pg.EndpointConfigMapName]
	if !ok {
		return fmt.Errorf("PostgreSQL endpoint ConfigMap %s not found", pg.EndpointConfigMapName)
	}
	requiredKeys := []string{"POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DATABASE", "POSTGRES_SSL_MODE", "POSTGRES_SSL_SERVER_NAME"}
	for _, key := range requiredKeys {
		if len(endpoint[key]) == 0 {
			return fmt.Errorf("PostgreSQL endpoint missing non-empty key %s", key)
		}
	}
	port, err := strconv.Atoi(string(endpoint["POSTGRES_PORT"]))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("POSTGRES_PORT must be an integer from 1 to 65535")
	}
	if got := string(endpoint["POSTGRES_HOST"]); got != pg.Host {
		return fmt.Errorf("POSTGRES_HOST %q does not match contract host %q", got, pg.Host)
	}
	if port != pg.Port {
		return fmt.Errorf("POSTGRES_PORT %d does not match contract port %d", port, pg.Port)
	}
	if got := string(endpoint["POSTGRES_DATABASE"]); got != pg.Database {
		return fmt.Errorf("POSTGRES_DATABASE %q does not match contract database %q", got, pg.Database)
	}
	if pg.Transport != "tls-verify-full" || string(endpoint["POSTGRES_SSL_MODE"]) != "verify-full" {
		return fmt.Errorf("PostgreSQL transport must be tls-verify-full/verify-full")
	}
	serverName := string(endpoint["POSTGRES_SSL_SERVER_NAME"])
	if serverName != pg.TLSServerName || serverName != pg.Host {
		return fmt.Errorf("POSTGRES_SSL_SERVER_NAME must match the contract TLS server name and host")
	}

	tlsSecret, ok := data[pg.TLSSecretName]
	if !ok {
		return fmt.Errorf("PostgreSQL TLS secret %s not found", pg.TLSSecretName)
	}
	caData, ok := tlsSecret["ca.crt"]
	if !ok {
		return fmt.Errorf("PostgreSQL TLS secret missing ca.crt")
	}
	caPool, err := parseCAPool(caData)
	if err != nil {
		return fmt.Errorf("PostgreSQL CA is invalid: %w", err)
	}
	tlsConfig := &tls.Config{ // #nosec G402 -- TLS 1.2 is the deliberate compatibility floor.
		MinVersion: tls.VersionTLS12,
		RootCAs:    caPool,
		ServerName: serverName,
	}

	if len(pg.Accounts) != len(canonicalAccounts) {
		return fmt.Errorf("PostgreSQL contract must declare exactly the five isolated accounts")
	}
	for secretName, expectedUser := range canonicalAccounts {
		declaredUser, ok := pg.Accounts[secretName]
		if !ok || declaredUser != expectedUser {
			return fmt.Errorf("PostgreSQL account %s must map to %s", secretName, expectedUser)
		}
		credentials, ok := data[secretName]
		if !ok {
			return fmt.Errorf("PostgreSQL account secret %s not found", secretName)
		}
		password := credentials["password"]
		if len(password) == 0 {
			return fmt.Errorf("PostgreSQL account secret %s missing non-empty password", secretName)
		}
		if err := validatePostgresAccount(ctx, pg, tlsConfig, expectedUser, string(password)); err != nil {
			return fmt.Errorf("PostgreSQL account %s: %w", expectedUser, err)
		}
	}
	return nil
}

func validatePostgresAccount(parent context.Context, pg contract.PostgresValidation, tlsConfig *tls.Config, user, password string) (returnErr error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig("")
	if err != nil {
		return fmt.Errorf("create connection config: %w", err)
	}
	config.Host = pg.Host
	config.Port = uint16(pg.Port) // #nosec G115 -- contract validation restricts the port to 1..65535.
	config.Database = pg.Database
	config.User = user
	config.Password = password
	config.TLSConfig = tlsConfig.Clone()
	config.ConnectTimeout = 5 * time.Second
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("connect with verified TLS: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, connection.Close(context.Background()))
	}()

	var database, identity string
	if err := connection.QueryRow(ctx, "select current_database(), current_user").Scan(&database, &identity); err != nil {
		return fmt.Errorf("read connection identity: %w", err)
	}
	if database != pg.Database || identity != user {
		return fmt.Errorf("connected as %s to %s, expected %s to %s", identity, database, user, pg.Database)
	}
	if err := validateAccountGrants(ctx, connection, user); err != nil {
		return err
	}
	return nil
}

func validateAccountGrants(ctx context.Context, connection *pgx.Conn, user string) error {
	switch user {
	case "schema_owner":
		return requireDatabasePrivilege(ctx, connection, "CREATE")
	case "keycloak_runtime":
		return requireSchemaPrivileges(ctx, connection, "keycloak", "USAGE", "CREATE")
	case "schema_migrator_runtime":
		if err := requireSchemaPrivileges(ctx, connection, "schema_migrator", "USAGE"); err != nil {
			return err
		}
		if err := requireAllTablePrivileges(ctx, connection, "schema_migrator", "SELECT", "INSERT", "UPDATE", "DELETE"); err != nil {
			return err
		}
		return requireAllSequencePrivileges(ctx, connection, "schema_migrator", "USAGE", "SELECT")
	case "atheros_search_runtime":
		if err := requireSchemaPrivileges(ctx, connection, "atheros_search", "USAGE"); err != nil {
			return err
		}
		if err := requireAllTablePrivileges(ctx, connection, "atheros_search", "SELECT"); err != nil {
			return err
		}
		if err := requireAllSequencePrivileges(ctx, connection, "atheros_search", "USAGE", "SELECT"); err != nil {
			return err
		}
		return requireTableGrants(ctx, connection, atherosSearchGrants())
	case "octopus_runtime":
		if err := requireSchemaPrivileges(ctx, connection, "octopus_core", "USAGE"); err != nil {
			return err
		}
		if err := requireAllTablePrivileges(ctx, connection, "octopus_core", "SELECT", "INSERT", "UPDATE", "DELETE"); err != nil {
			return err
		}
		if err := requireAllSequencePrivileges(ctx, connection, "octopus_core", "USAGE", "SELECT"); err != nil {
			return err
		}
		if err := requireSchemaPrivileges(ctx, connection, "atheros_search", "USAGE"); err != nil {
			return err
		}
		if err := requireAllTablePrivileges(ctx, connection, "atheros_search", "SELECT"); err != nil {
			return err
		}
		if err := requireAllSequencePrivileges(ctx, connection, "atheros_search", "USAGE", "SELECT"); err != nil {
			return err
		}
		return requireTableGrants(ctx, connection, octopusAtherosGrants())
	default:
		return fmt.Errorf("no grant matrix is defined for account %s", user)
	}
}

func requireDatabasePrivilege(ctx context.Context, connection *pgx.Conn, privilege string) error {
	var allowed bool
	if err := connection.QueryRow(ctx, "select has_database_privilege(current_user, current_database(), $1)", privilege).Scan(&allowed); err != nil {
		return fmt.Errorf("check database privilege %s: %w", privilege, err)
	}
	if !allowed {
		return fmt.Errorf("missing database privilege %s", privilege)
	}
	return nil
}

func requireSchemaPrivileges(ctx context.Context, connection *pgx.Conn, schema string, privileges ...string) error {
	for _, privilege := range privileges {
		var allowed bool
		if err := connection.QueryRow(ctx, "select has_schema_privilege(current_user, $1, $2)", schema, privilege).Scan(&allowed); err != nil {
			return fmt.Errorf("check %s privilege on schema %s: %w", privilege, schema, err)
		}
		if !allowed {
			return fmt.Errorf("missing %s privilege on schema %s", privilege, schema)
		}
	}
	return nil
}

func requireAllTablePrivileges(ctx context.Context, connection *pgx.Conn, schema string, privileges ...string) error {
	for _, privilege := range privileges {
		var allowed bool
		query := `select count(*) > 0 and bool_and(has_table_privilege(current_user, format('%I.%I', schemaname, tablename), $2)) from pg_tables where schemaname = $1`
		if err := connection.QueryRow(ctx, query, schema, privilege).Scan(&allowed); err != nil {
			return fmt.Errorf("check %s on all %s tables: %w", privilege, schema, err)
		}
		if !allowed {
			return fmt.Errorf("missing %s on one or more tables in schema %s", privilege, schema)
		}
	}
	return nil
}

func requireAllSequencePrivileges(ctx context.Context, connection *pgx.Conn, schema string, privileges ...string) error {
	for _, privilege := range privileges {
		var allowed bool
		query := `select count(*) = 0 or bool_and(has_sequence_privilege(current_user, format('%I.%I', sequence_schema, sequence_name), $2)) from information_schema.sequences where sequence_schema = $1`
		if err := connection.QueryRow(ctx, query, schema, privilege).Scan(&allowed); err != nil {
			return fmt.Errorf("check %s on all %s sequences: %w", privilege, schema, err)
		}
		if !allowed {
			return fmt.Errorf("missing %s on one or more sequences in schema %s", privilege, schema)
		}
	}
	return nil
}

func requireTableGrants(ctx context.Context, connection *pgx.Conn, grants []tableGrant) error {
	for _, grant := range grants {
		for _, privilege := range grant.privileges {
			var allowed bool
			query := `select case when to_regclass($1) is null then false else has_table_privilege(current_user, to_regclass($1), $2) end`
			if err := connection.QueryRow(ctx, query, grant.table, privilege).Scan(&allowed); err != nil {
				return fmt.Errorf("check %s on %s: %w", privilege, grant.table, err)
			}
			if !allowed {
				return fmt.Errorf("missing %s on %s", privilege, grant.table)
			}
		}
	}
	return nil
}

func atherosSearchGrants() []tableGrant {
	return []tableGrant{
		{table: "atheros_search.embedding_jobs", privileges: []string{"UPDATE"}},
		{table: "atheros_search.search_vectors_event", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_vectors_device", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_vectors_behaviour", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_vectors_sequence", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.worker_heartbeat", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_queries", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_query_results", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.search_feedback", privileges: []string{"INSERT", "UPDATE"}},
		{table: "atheros_search.merge_decisions", privileges: []string{"INSERT"}},
	}
}

func octopusAtherosGrants() []tableGrant {
	crud := []string{"INSERT", "UPDATE", "DELETE"}
	deleteOnly := []string{"DELETE"}
	grants := []tableGrant{
		{table: "atheros_search.search_documents", privileges: crud},
		{table: "atheros_search.search_document_tokens", privileges: crud},
		{table: "atheros_search.search_document_tags", privileges: crud},
		{table: "atheros_search.search_filter_values", privileges: crud},
		{table: "atheros_search.embedding_jobs", privileges: crud},
		{table: "atheros_search.search_vectors_event", privileges: deleteOnly},
		{table: "atheros_search.search_vectors_device", privileges: deleteOnly},
		{table: "atheros_search.search_vectors_behaviour", privileges: deleteOnly},
		{table: "atheros_search.search_vectors_sequence", privileges: deleteOnly},
	}
	for _, table := range []string{
		"behaviour_snapshots", "baseline_profiles", "frame_sequences", "sequence_transitions",
		"timing_profiles", "similarity_pairs", "threat_signals", "ap_risk_scores",
		"sequence_transition_contributions", "sequence_previous_totals", "graph_nodes", "graph_edges",
		"inventory_devices", "identity_clusters", "identity_cluster_members", "merge_candidates",
	} {
		grants = append(grants, tableGrant{table: "atheros_search." + table, privileges: crud})
	}
	return grants
}
