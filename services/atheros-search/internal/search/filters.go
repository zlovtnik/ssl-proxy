package search

import (
	"fmt"
	"strings"
	"time"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

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
	if filters.SourceMac != "" {
		add("lower(se.source_mac) = lower($%d)", filters.SourceMac)
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
		out.Clauses = append(out.Clauses, "(coalesce(se.handshake_captured, false) = true or exists (select 1 from jsonb_array_elements_text(case when jsonb_typeof(se.payload->'tags') = 'array' then se.payload->'tags' else '[]'::jsonb end) t(tag) where t.tag like 'threat:%'))")
	}
	for _, tag := range filters.Tags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			add("se.payload->'tags' ? $%d", tag)
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
	if filters.SourceMac != "" {
		add("lower(e.source_mac) = lower($%d)", filters.SourceMac)
	}
	if filters.ObservedAfter != nil {
		add("e.source_observed_at >= $%d", filters.ObservedAfter.AsTime())
	}
	if filters.ObservedBefore != nil {
		add("e.source_observed_at <= $%d", filters.ObservedBefore.AsTime())
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
