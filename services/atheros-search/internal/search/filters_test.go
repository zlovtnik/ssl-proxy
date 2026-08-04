package search

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func TestResultMatchesFilters(t *testing.T) {
	observed := time.Unix(100, 0).UTC()
	result := RawResult{
		SourceMAC: "aa:bb", LocationID: "lab", SensorID: "sensor-a",
		SSID: "Lab Network", FrameSubtype: "probe_request", ObservedAt: &observed,
		Tags: []string{"threat:rogue", "wireless"}, securityFlags: 4, handshakeCaptured: true,
	}
	require.True(t, resultMatchesFilters(result, &searchv1.SearchFilters{
		LocationIds: []string{"lab"}, SensorIds: []string{"sensor-a"}, Ssid: "network",
		SourceMacs: []string{"AA:BB"}, FrameSubtypes: []string{"probe_request"},
		ObservedAfter: timestamppb.New(observed.Add(-time.Second)), ObservedBefore: timestamppb.New(observed.Add(time.Second)),
		ThreatOnly: true, HandshakeOnly: true, SecurityFlagsMask: 4, Tags: []string{"WIRELESS"},
	}))
}

func TestResultMatchesFiltersRejectsMissingRequirements(t *testing.T) {
	result := RawResult{SourceMAC: "aa:bb", Tags: []string{"normal"}}
	require.False(t, resultMatchesFilters(result, &searchv1.SearchFilters{SourceMac: "cc:dd"}))
	require.False(t, resultMatchesFilters(result, &searchv1.SearchFilters{ThreatOnly: true}))
	require.False(t, resultMatchesFilters(result, &searchv1.SearchFilters{SecurityFlagsMask: 2}))
}

func TestFilterSourceMACsNormalizesAndDeduplicates(t *testing.T) {
	got := filterSourceMACs(&searchv1.SearchFilters{
		SourceMac: "AA:BB", SourceMacs: []string{"aa:bb", "CC:DD"},
	})
	require.Equal(t, []string{"aa:bb", "cc:dd"}, got)
}
