package validate

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type objectPrivileges map[string]map[string]bool

type rolePrivileges struct {
	tables    objectPrivileges
	sequences objectPrivileges
}

func TestAtherosSearchGrantMatricesMatchCanonicalSQL(t *testing.T) {
	t.Parallel()

	fixture, err := os.ReadFile(canonicalAtherosGrantFixture(t))
	if err != nil {
		t.Fatalf("read canonical grant fixture: %v", err)
	}
	parsed := parseGrantFixture(t, string(fixture))

	tests := []struct {
		name      string
		role      string
		tables    []tableGrant
		sequences []sequenceGrant
	}{
		{
			name:      "Atheros Search runtime",
			role:      "{{ATHEROS_SEARCH_ACCOUNT}}",
			tables:    atherosSearchGrants(),
			sequences: atherosSearchSequenceGrants(),
		},
		{
			name:   "Octopus runtime",
			role:   "{{OCTOPUS_ACCOUNT}}",
			tables: octopusAtherosGrants(),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			want, ok := parsed[test.role]
			if !ok {
				t.Fatalf("canonical fixture has no grants for %s", test.role)
			}
			got := rolePrivileges{
				tables:    tablePrivilegeMap(test.tables),
				sequences: sequencePrivilegeMap(test.sequences),
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Go grant matrix differs from canonical SQL\nGo:  %#v\nSQL: %#v", got, want)
			}
		})
	}
}

func TestAtherosSearchRuntimeExcludesCoordinatorAndUnknownTables(t *testing.T) {
	t.Parallel()

	grants := tablePrivilegeMap(atherosSearchGrants())
	for _, table := range []string{
		"atheros_search.identity_clusters",
		"atheros_search.identity_cluster_members",
		"atheros_search.merge_candidates",
		"atheros_search.merge_decisions",
		"atheros_search.search_query_results",
		"atheros_search.search_feedback",
		"atheros_search.search_filter_values",
	} {
		if _, ok := grants[table]; ok {
			t.Errorf("Atheros Search runtime must not validate access to %s", table)
		}
	}
}

func TestOctopusCoreGrantMatrixMatchesCanonicalSQL(t *testing.T) {
	t.Parallel()

	fixture, err := os.ReadFile(canonicalGrantFixture(t, "octopus_core"))
	if err != nil {
		t.Fatalf("read canonical grant fixture: %v", err)
	}
	want, ok := parseGrantFixture(t, string(fixture))["{{OCTOPUS_ACCOUNT}}"]
	if !ok {
		t.Fatal("canonical fixture has no grants for {{OCTOPUS_ACCOUNT}}")
	}
	got := rolePrivileges{
		tables:    tablePrivilegeMap(octopusCoreGrants()),
		sequences: sequencePrivilegeMap(octopusCoreSequenceGrants()),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Go grant matrix differs from canonical SQL\nGo:  %#v\nSQL: %#v", got, want)
	}
}

func canonicalAtherosGrantFixture(t *testing.T) string {
	return canonicalGrantFixture(t, "atheros_search")
}

func canonicalGrantFixture(t *testing.T, schema string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file path")
	}
	return filepath.Clean(filepath.Join(
		filepath.Dir(filename),
		"..", "..", "..", "..",
		"sql", "postgres", schema, "grants", "least_privilege.sql.tmpl",
	))
}

func parseGrantFixture(t *testing.T, sql string) map[string]rolePrivileges {
	t.Helper()

	var normalized strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "--", 2)[0])
		if line != "" {
			normalized.WriteString(line)
			normalized.WriteByte(' ')
		}
	}

	result := make(map[string]rolePrivileges)
	for _, rawStatement := range strings.Split(normalized.String(), ";") {
		statement := strings.TrimSpace(rawStatement)
		if statement == "" {
			continue
		}
		upper := strings.ToUpper(statement)
		if !strings.HasPrefix(upper, "GRANT ") {
			t.Fatalf("unsupported statement in canonical grant fixture: %s", statement)
		}
		onIndex := strings.Index(upper, " ON ")
		toIndex := strings.LastIndex(upper, " TO ")
		if onIndex < 0 || toIndex < 0 || toIndex <= onIndex {
			t.Fatalf("cannot parse canonical grant statement: %s", statement)
		}

		privileges := commaSeparated(statement[len("GRANT "):onIndex])
		targets := strings.TrimSpace(statement[onIndex+len(" ON ") : toIndex])
		roles := commaSeparated(statement[toIndex+len(" TO "):])
		kind := "table"
		upperTargets := strings.ToUpper(targets)
		switch {
		case strings.HasPrefix(upperTargets, "SCHEMA "), strings.HasPrefix(upperTargets, "TYPE "):
			continue
		case strings.HasPrefix(upperTargets, "SEQUENCE "):
			kind = "sequence"
			targets = strings.TrimSpace(targets[len("SEQUENCE "):])
		}

		for _, role := range roles {
			roleGrant := result[role]
			if roleGrant.tables == nil {
				roleGrant.tables = make(objectPrivileges)
				roleGrant.sequences = make(objectPrivileges)
			}
			objects := roleGrant.tables
			if kind == "sequence" {
				objects = roleGrant.sequences
			}
			for _, object := range commaSeparated(targets) {
				if objects[object] == nil {
					objects[object] = make(map[string]bool)
				}
				for _, privilege := range privileges {
					objects[object][strings.ToUpper(privilege)] = true
				}
			}
			result[role] = roleGrant
		}
	}
	return result
}

func commaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func tablePrivilegeMap(grants []tableGrant) objectPrivileges {
	result := make(objectPrivileges)
	for _, grant := range grants {
		result[grant.table] = privilegeSet(grant.privileges)
	}
	return result
}

func sequencePrivilegeMap(grants []sequenceGrant) objectPrivileges {
	result := make(objectPrivileges)
	for _, grant := range grants {
		result[grant.sequence] = privilegeSet(grant.privileges)
	}
	return result
}

func privilegeSet(privileges []string) map[string]bool {
	result := make(map[string]bool, len(privileges))
	for _, privilege := range privileges {
		result[privilege] = true
	}
	return result
}
