package search

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBuildEventTextGolden(t *testing.T) {
	observed := time.Date(2026, 6, 2, 14, 30, 0, 0, time.UTC)
	got := BuildEventText(AuditEntry{
		FrameType:         "management",
		FrameSubtype:      "probe_request",
		AppProtocol:       "mdns",
		SecurityFlags:     "4",
		WPSDeviceName:     "Living_Room_AP",
		SSID:              "corp",
		HandshakeCaptured: "true",
		ObservedAt:        &observed,
	})
	require.Equal(t, "kind: event\nframe_type: management\nframe_subtype: probe_request\napp_protocol: mdns\nsecurity_flags: 4\nwps_device_name: Living Room AP\nssid: corp\nhandshake_captured: true\nhour_of_day: 14\nday_of_week: tuesday\nis_weekend: false\nis_business_hours: true", got)
}

func TestBuildQueryTextPrefixesKind(t *testing.T) {
	require.Equal(t, "kind: frame_sequence\nquery: probe_request deauthentication", BuildQueryText("probe_request deauthentication", "frame_sequence"))
}

func TestClampWordsPreservesLineBreaks(t *testing.T) {
	got := clampWords("one two\nthree four\nfive six", 4)

	require.Equal(t, "one two\nthree four...", got)
}
