package search

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type AuditEntry struct {
	FrameType         string
	FrameSubtype      string
	AppProtocol       string
	TransportProtocol string
	SecurityFlags     string
	DNSQueryName      string
	MDNSName          string
	DHCPHostname      string
	WPSDeviceName     string
	WPSManufacturer   string
	WPSModelName      string
	SSID              string
	DeviceFingerprint string
	HandshakeCaptured string
	Protected         string
	ChannelNumber     string
	SignalDBM         string
	Retry             string
	MoreData          string
	PowerSave         string
	ObservedAt        *time.Time
}

type BehaviourSnapshot struct {
	EventCount            int64
	ProtocolMix           string
	FrameTypeDistribution string
	SignalMinDBM          string
	SignalMaxDBM          string
	SignalAvgDBM          string
	RetryCount            int64
	ProtectedCount        int64
	UnprotectedCount      int64
	UniqueBSSIDCount      int64
	MacRotationIndicators string
}

type FrameSequence struct {
	SequenceTokens string
	SemanticTokens string
	FrameCount     int64
}

type Device struct {
	MACID       string
	DisplayName string
	Username    string
	Hostname    string
	OSHint      string
	MACHint     string
	FirstSeen   *time.Time
	LastSeen    *time.Time
	ClusterSize int64
}

func BuildEventText(entry AuditEntry) string {
	fields := []struct {
		name  string
		value string
	}{
		{"frame_type", entry.FrameType},
		{"frame_subtype", entry.FrameSubtype},
		{"app_protocol", entry.AppProtocol},
		{"transport_protocol", entry.TransportProtocol},
		{"security_flags", entry.SecurityFlags},
		{"dns_query_name", entry.DNSQueryName},
		{"mdns_name", entry.MDNSName},
		{"dhcp_hostname", entry.DHCPHostname},
		{"wps_device_name", normalizeWPSName(entry.WPSDeviceName)},
		{"wps_manufacturer", entry.WPSManufacturer},
		{"wps_model_name", entry.WPSModelName},
		{"ssid", entry.SSID},
		{"device_fingerprint", entry.DeviceFingerprint},
		{"handshake_captured", entry.HandshakeCaptured},
		{"protected", entry.Protected},
		{"channel_number", entry.ChannelNumber},
		{"signal_dbm", entry.SignalDBM},
		{"retry", entry.Retry},
		{"more_data", entry.MoreData},
		{"power_save", entry.PowerSave},
	}
	lines := []string{"kind: event"}
	for _, field := range fields {
		appendValue(&lines, field.name, field.value)
	}
	if entry.ObservedAt != nil {
		lines = append(lines, temporalLines(*entry.ObservedAt)...)
	}
	return clampWords(strings.Join(lines, "\n"), 128)
}

func BuildBehaviourText(snapshot BehaviourSnapshot) string {
	lines := []string{"kind: behaviour_window"}
	appendValue(&lines, "event_count", fmt.Sprint(snapshot.EventCount))
	appendValue(&lines, "protocol_mix", snapshot.ProtocolMix)
	appendValue(&lines, "frame_type_distribution", snapshot.FrameTypeDistribution)
	appendValue(&lines, "signal_min_dbm", snapshot.SignalMinDBM)
	appendValue(&lines, "signal_max_dbm", snapshot.SignalMaxDBM)
	appendValue(&lines, "signal_avg_dbm", snapshot.SignalAvgDBM)
	appendValue(&lines, "retry_count", fmt.Sprint(snapshot.RetryCount))
	appendValue(&lines, "protected_count", fmt.Sprint(snapshot.ProtectedCount))
	appendValue(&lines, "unprotected_count", fmt.Sprint(snapshot.UnprotectedCount))
	appendValue(&lines, "unique_bssid_count", fmt.Sprint(snapshot.UniqueBSSIDCount))
	appendValue(&lines, "mac_rotation_indicators", snapshot.MacRotationIndicators)
	return clampWords(strings.Join(lines, "\n"), 128)
}

func BuildSequenceText(seq FrameSequence) string {
	lines := []string{"kind: frame_sequence"}
	appendValue(&lines, "sequence_tokens", seq.SequenceTokens)
	appendValue(&lines, "semantic_tokens", seq.SemanticTokens)
	appendValue(&lines, "frame_count", fmt.Sprint(seq.FrameCount))
	return clampWords(strings.Join(lines, "\n"), 128)
}

func BuildDeviceText(device Device) string {
	lines := []string{"kind: device"}
	appendValue(&lines, "mac_id", device.MACID)
	appendValue(&lines, "display_name", device.DisplayName)
	appendValue(&lines, "username", device.Username)
	appendValue(&lines, "hostname", device.Hostname)
	appendValue(&lines, "os_hint", device.OSHint)
	appendValue(&lines, "mac_hint", device.MACHint)
	if device.FirstSeen != nil {
		appendValue(&lines, "first_seen", device.FirstSeen.Format(time.RFC3339))
	}
	if device.LastSeen != nil {
		appendValue(&lines, "last_seen", device.LastSeen.Format(time.RFC3339))
	}
	appendValue(&lines, "cluster_size", fmt.Sprint(device.ClusterSize))
	return clampWords(strings.Join(lines, "\n"), 128)
}

func BuildQueryText(query string, kind string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return "kind: " + kind + "\nquery:"
	}
	return "kind: " + kind + "\nquery: " + query
}

func appendValue(lines *[]string, name, value string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "null") {
		return
	}
	*lines = append(*lines, name+": "+value)
}

func normalizeWPSName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "_", " ")
	return strings.Join(strings.Fields(value), " ")
}

func temporalLines(t time.Time) []string {
	weekday := strings.ToLower(t.Weekday().String())
	lines := []string{
		fmt.Sprintf("hour_of_day: %02d", t.Hour()),
		"day_of_week: " + weekday,
	}
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		lines = append(lines, "is_weekend: true")
	} else {
		lines = append(lines, "is_weekend: false")
	}
	if t.Hour() >= 9 && t.Hour() < 17 {
		lines = append(lines, "is_business_hours: true")
	} else {
		lines = append(lines, "is_business_hours: false")
	}
	return lines
}

func clampWords(text string, maxWords int) string {
	words := strings.Fields(text)
	if len(words) <= maxWords {
		return text
	}
	return strings.Join(words[:maxWords], " ") + "..."
}

func TagsFromJSON(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}
