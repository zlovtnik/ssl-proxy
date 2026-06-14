package search

import (
	"fmt"
	"strings"
	"time"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

const wirelessTagsSQL = "case when se.tags is not null and se.tags <> '[]'::jsonb then se.tags when jsonb_typeof(se.payload->'tags') = 'array' then se.payload->'tags' else '[]'::jsonb end"

const compactEventDetailSQL = "case when se.dedupe_key is null then '{}'::jsonb when se.payload is not null then se.payload else jsonb_strip_nulls(jsonb_build_object(" +
	"'dedupe_key', se.dedupe_key, " +
	"'observed_at', se.observed_at, " +
	"'stream_name', se.stream_name, " +
	"'payload_archived', coalesce(se.payload_archived, false), " +
	"'payload_archive_uri', se.payload_archive_uri, " +
	"'payload_archived_at', se.payload_archived_at, " +
	"'archived_payload_bytes', se.archived_payload_bytes, " +
	"'event_type', se.event_type, " +
	"'frame_type', se.frame_type, " +
	"'frame_subtype', se.frame_subtype, " +
	"'source_mac', se.source_mac, " +
	"'transmitter_mac', se.transmitter_mac, " +
	"'receiver_mac', se.receiver_mac, " +
	"'bssid', coalesce(se.bssid, se.destination_bssid), " +
	"'ssid', se.ssid, " +
	"'sensor_id', se.sensor_id, " +
	"'location_id', se.location_id, " +
	"'risk_score', se.risk_score, " +
	"'tags', " + wirelessTagsSQL +
	")) end"

type SQLFilter struct {
	Clauses []string
	Args    []any
}

func BuildWirelessFilters(filters *searchv1.SearchFilters, start int) SQLFilter {
	if filters == nil {
		return SQLFilter{}
	}
	next := start
	out := SQLFilter{}
	add := func(clause string, value any) {
		out.Clauses = append(out.Clauses, fmt.Sprintf(clause, next))
		out.Args = append(out.Args, value)
		next++
	}
	if len(filters.LocationIds) > 0 {
		add("coalesce(se.location_id, '') = any($%d::text[])", filters.LocationIds)
	}
	if len(filters.SensorIds) > 0 {
		add("coalesce(se.sensor_id, '') = any($%d::text[])", filters.SensorIds)
	}
	if filters.Ssid != "" {
		add("se.ssid ilike $%d", "%"+escapeLike(filters.Ssid)+"%")
	}
	sourceMACs := filterSourceMACs(filters)
	if len(sourceMACs) > 0 {
		add("lower(se.source_mac) = any($%d::text[])", sourceMACs)
	}
	if len(filters.FrameSubtypes) > 0 {
		add("se.frame_subtype = any($%d::text[])", filters.FrameSubtypes)
	}
	if filters.ObservedAfter != nil {
		add("se.observed_at >= $%d", filters.ObservedAfter.AsTime())
	}
	if filters.ObservedBefore != nil {
		add("se.observed_at <= $%d", filters.ObservedBefore.AsTime())
	}
	if filters.SecurityFlagsMask != 0 {
		add("(coalesce(se.security_flags, 0) & $%d) <> 0", filters.SecurityFlagsMask)
	}
	if filters.HandshakeOnly {
		out.Clauses = append(out.Clauses, "coalesce(se.handshake_captured, false) = true")
	}
	if filters.ThreatOnly {
		out.Clauses = append(out.Clauses, "(coalesce(se.handshake_captured, false) = true or exists (select 1 from jsonb_array_elements_text("+wirelessTagsSQL+") t(tag) where t.tag like 'threat:%'))")
	}
	for _, tag := range filters.Tags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			add(wirelessTagsSQL+" ? $%d", tag)
		}
	}
	return out
}

func BuildEmbeddingFilters(filters *searchv1.SearchFilters, start int) SQLFilter {
	if filters == nil {
		return SQLFilter{}
	}
	next := start
	out := SQLFilter{}
	add := func(clause string, value any) {
		out.Clauses = append(out.Clauses, fmt.Sprintf(clause, next))
		out.Args = append(out.Args, value)
		next++
	}
	if len(filters.LocationIds) > 0 {
		add("coalesce(e.source_location_id, '') = any($%d::text[])", filters.LocationIds)
	}
	if len(filters.SensorIds) > 0 {
		add("coalesce(e.source_sensor_id, '') = any($%d::text[])", filters.SensorIds)
	}
	sourceMACs := filterSourceMACs(filters)
	if len(sourceMACs) > 0 {
		add("lower(e.source_mac) = any($%d::text[])", sourceMACs)
	}
	if filters.ObservedAfter != nil {
		add("e.source_observed_at >= $%d", filters.ObservedAfter.AsTime())
	}
	if filters.ObservedBefore != nil {
		add("e.source_observed_at <= $%d", filters.ObservedBefore.AsTime())
	}
	return out
}

func filterSourceMACs(filters *searchv1.SearchFilters) []string {
	if filters == nil {
		return nil
	}
	values := make([]string, 0, 1+len(filters.SourceMacs))
	if filters.SourceMac != "" {
		values = append(values, filters.SourceMac)
	}
	values = append(values, filters.SourceMacs...)
	return normalizeLowerList(values)
}

func normalizeLowerList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func WhereSQL(base []string, extra []string) string {
	all := append([]string{}, base...)
	all = append(all, extra...)
	if len(all) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(all, " AND ")
}

func TimePtr(t time.Time, ok bool) *time.Time {
	if !ok {
		return nil
	}
	return &t
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return value
}
