package textbuilder

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

func TestEventRowToInputUsesSemanticFieldsAndMetadata(t *testing.T) {
	observed := time.Date(2026, 6, 5, 14, 0, 0, 0, time.UTC)
	row := EventRow{
		ObservedAt:    pgtype.Timestamptz{Time: observed, Valid: true},
		StreamName:    "wireless.audit",
		SensorID:      "sensor-a",
		LocationID:    "lab",
		SourceMAC:     "aa:bb:cc:dd:ee:ff",
		FrameType:     "management",
		FrameSubtype:  "probe_request",
		WPSDeviceName: `55" Hisense Roku TV`,
		Retry:         "0",
		Protected:     "false",
		SSID:          "corp",
	}

	input := eventRowToInput(row)

	require.Contains(t, input.Text, "kind: event")
	require.Contains(t, input.Text, "frame_type: management")
	require.Contains(t, input.Text, "frame_subtype: probe_request")
	require.Contains(t, input.Text, "wps_device_name: hisense")
	require.Contains(t, input.Text, "ssid: corp")
	require.NotContains(t, input.Text, "retry:")
	require.NotContains(t, input.Text, "protected:")
	require.Contains(t, input.Text, "hour_of_day: 14")
	require.Equal(t, &observed, input.SourceObservedAt)
	require.Equal(t, "wireless.audit", input.SourceStreamName)
	require.Equal(t, "sensor-a", input.SourceSensorID)
	require.Equal(t, "lab", input.SourceLocationID)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", input.SourceMAC)
}
