package textbuilder

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestDeviceRowToInputIncludesClusterSize(t *testing.T) {
	lastSeen := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	row := DeviceRow{
		MACID:       "aa:bb:cc:dd:ee:ff",
		DisplayName: "Ops Laptop",
		Username:    "none",
		Hostname:    "ops-1",
		LastSeen:    pgtype.Timestamptz{Time: lastSeen, Valid: true},
		ClusterSize: 3,
	}

	input := deviceRowToInput(row)

	require.Contains(t, input.Text, "kind: device")
	require.Contains(t, input.Text, "mac_id: aa:bb:cc:dd:ee:ff")
	require.Contains(t, input.Text, "display_name: Ops Laptop")
	require.Contains(t, input.Text, "hostname: ops-1")
	require.Contains(t, input.Text, "cluster_size: 3")
	require.NotContains(t, input.Text, "username:")
	require.Equal(t, &lastSeen, input.SourceObservedAt)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", input.SourceMAC)
}
