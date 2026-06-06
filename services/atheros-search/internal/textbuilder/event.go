package textbuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

var eventSemanticFields = []string{
	"frame_type",
	"frame_subtype",
	"app_protocol",
	"transport_protocol",
	"security_flags",
	"dns_query_name",
	"mdns_name",
	"dhcp_hostname",
	"wps_device_name",
	"wps_manufacturer",
	"wps_model_name",
	"ssid",
	"device_fingerprint",
	"handshake_captured",
	"protected",
	"channel_number",
	"signal_dbm",
	"retry",
	"more_data",
	"power_save",
}

type EventRow struct {
	DedupeKey         string
	ObservedAt        pgtype.Timestamptz
	StreamName        string
	SensorID          string
	LocationID        string
	SourceMAC         string
	SSID              string
	FrameType         string
	FrameSubtype      string
	ChannelNumber     string
	SignalDBM         string
	Retry             string
	MoreData          string
	PowerSave         string
	Protected         string
	SecurityFlags     string
	AppProtocol       string
	TransportProtocol string
	DNSQueryName      string
	MDNSName          string
	DHCPHostname      string
	WPSDeviceName     string
	WPSManufacturer   string
	WPSModelName      string
	DeviceFingerprint string
	HandshakeCaptured string
}

func buildEventsBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob, out map[string]db.EmbeddingInput) error {
	rows, err := pool.Query(ctx, `
SELECT
  dedupe_key,
  observed_at,
  coalesce(stream_name, ''),
  coalesce(sensor_id, payload->>'sensor_id', ''),
  coalesce(location_id, payload->>'location_id', ''),
  lower(coalesce(source_mac, payload->>'source_mac', '')),
  coalesce(ssid, payload->>'ssid', ''),
  coalesce(frame_type, payload->>'frame_type', ''),
  coalesce(payload->>'frame_subtype', ''),
  coalesce(channel_number::text, payload->>'channel_number', payload->>'channel', ''),
  coalesce(signal_dbm::text, payload->>'signal_dbm', ''),
  coalesce(retry::text, payload->>'retry', ''),
  coalesce(more_data::text, payload->>'more_data', ''),
  coalesce(power_save::text, payload->>'power_save', ''),
  coalesce(protected::text, payload->>'protected', ''),
  coalesce(security_flags::text, payload->>'security_flags', ''),
  coalesce(app_protocol, payload->>'app_protocol', ''),
  coalesce(transport_protocol, payload->>'transport_protocol', ''),
  coalesce(dns_query_name, payload->>'dns_query_name', ''),
  coalesce(mdns_name, payload->>'mdns_name', ''),
  coalesce(dhcp_hostname, payload->>'dhcp_hostname', ''),
  coalesce(wps_device_name, payload->>'wps_device_name', ''),
  coalesce(wps_manufacturer, payload->>'wps_manufacturer', ''),
  coalesce(wps_model_name, payload->>'wps_model_name', ''),
  coalesce(device_fingerprint, payload->>'device_fingerprint', ''),
  coalesce(handshake_captured::text, payload->>'handshake_captured', '')
FROM sync_events_expanded
WHERE dedupe_key = ANY($1::text[])
`, sourceKeys(jobs))
	if err != nil {
		return fmt.Errorf("event batch query failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row EventRow
		if err := rows.Scan(
			&row.DedupeKey,
			&row.ObservedAt,
			&row.StreamName,
			&row.SensorID,
			&row.LocationID,
			&row.SourceMAC,
			&row.SSID,
			&row.FrameType,
			&row.FrameSubtype,
			&row.ChannelNumber,
			&row.SignalDBM,
			&row.Retry,
			&row.MoreData,
			&row.PowerSave,
			&row.Protected,
			&row.SecurityFlags,
			&row.AppProtocol,
			&row.TransportProtocol,
			&row.DNSQueryName,
			&row.MDNSName,
			&row.DHCPHostname,
			&row.WPSDeviceName,
			&row.WPSManufacturer,
			&row.WPSModelName,
			&row.DeviceFingerprint,
			&row.HandshakeCaptured,
		); err != nil {
			return fmt.Errorf("scan event row: %w", err)
		}
		out[row.DedupeKey] = eventRowToInput(row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read event rows: %w", err)
	}
	return nil
}

func eventRowToInput(row EventRow) db.EmbeddingInput {
	lines := []string{"kind: event"}
	for _, field := range eventSemanticFields {
		value := row.GetField(field)
		if field == "wps_device_name" {
			value = NormalizeWPSName(value)
		}
		AppendValue(&lines, field, value)
	}
	if row.ObservedAt.Valid {
		lines = append(lines, TemporalContextLines(row.ObservedAt.Time)...)
	}
	return db.EmbeddingInput{
		Text:             clampDefault(strings.Join(lines, "\n")),
		SourceObservedAt: optionalTime(row.ObservedAt.Valid, row.ObservedAt.Time),
		SourceStreamName: row.StreamName,
		SourceSensorID:   row.SensorID,
		SourceLocationID: row.LocationID,
		SourceMAC:        row.SourceMAC,
	}
}

func (r EventRow) GetField(name string) string {
	switch name {
	case "frame_type":
		return r.FrameType
	case "frame_subtype":
		return r.FrameSubtype
	case "app_protocol":
		return r.AppProtocol
	case "transport_protocol":
		return r.TransportProtocol
	case "security_flags":
		return r.SecurityFlags
	case "dns_query_name":
		return r.DNSQueryName
	case "mdns_name":
		return r.MDNSName
	case "dhcp_hostname":
		return r.DHCPHostname
	case "wps_device_name":
		return r.WPSDeviceName
	case "wps_manufacturer":
		return r.WPSManufacturer
	case "wps_model_name":
		return r.WPSModelName
	case "ssid":
		return r.SSID
	case "device_fingerprint":
		return r.DeviceFingerprint
	case "handshake_captured":
		return r.HandshakeCaptured
	case "protected":
		return r.Protected
	case "channel_number":
		return r.ChannelNumber
	case "signal_dbm":
		return r.SignalDBM
	case "retry":
		return r.Retry
	case "more_data":
		return r.MoreData
	case "power_save":
		return r.PowerSave
	default:
		return ""
	}
}
