package search

import (
	"strings"
	"time"

	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func resultMatchesFilters(result RawResult, filters *searchv1.SearchFilters) bool {
	if filters == nil {
		return true
	}
	if !matchesFoldList(result.LocationID, filters.LocationIds) ||
		!matchesFoldList(result.SensorID, filters.SensorIds) ||
		!matchesFoldList(result.FrameSubtype, filters.FrameSubtypes) {
		return false
	}
	if ssid := strings.TrimSpace(filters.Ssid); ssid != "" && !strings.Contains(strings.ToLower(result.SSID), strings.ToLower(ssid)) {
		return false
	}
	if sourceMACs := filterSourceMACs(filters); len(sourceMACs) > 0 && !containsFold(sourceMACs, result.SourceMAC) {
		return false
	}
	if filters.ObservedAfter != nil && (result.ObservedAt == nil || result.ObservedAt.Before(filters.ObservedAfter.AsTime())) {
		return false
	}
	if filters.ObservedBefore != nil && (result.ObservedAt == nil || result.ObservedAt.After(filters.ObservedBefore.AsTime())) {
		return false
	}
	if filters.SecurityFlagsMask != 0 && result.securityFlags&filters.SecurityFlagsMask == 0 {
		return false
	}
	if filters.HandshakeOnly && !result.handshakeCaptured {
		return false
	}
	if filters.ThreatOnly && !result.handshakeCaptured && !hasThreatTag(result.Tags) {
		return false
	}
	for _, required := range normalizeLowerList(filters.Tags) {
		if !containsFold(result.Tags, required) {
			return false
		}
	}
	return true
}

func filterResults(results []RawResult, filters *searchv1.SearchFilters, limit int) []RawResult {
	out := make([]RawResult, 0, minInt(limit, len(results)))
	for _, result := range results {
		if !resultMatchesFilters(result, filters) {
			continue
		}
		out = append(out, result)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func hasThreatTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tag)), "threat:") {
			return true
		}
	}
	return false
}

func matchesFoldList(value string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	return containsFold(allowed, value)
}

func containsFold(values []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, candidate := range values {
		if strings.EqualFold(strings.TrimSpace(candidate), value) {
			return true
		}
	}
	return false
}

func filterSourceMACs(filters *searchv1.SearchFilters) []string {
	if filters == nil {
		return nil
	}
	values := make([]string, 0, 1+len(filters.SourceMacs))
	values = append(values, filters.SourceMac)
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
