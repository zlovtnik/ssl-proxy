package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
	searchpkg "github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
)

const embedderWorkerName = "atheros-search"

type embeddingJob struct {
	JobID          int64
	SourceTable    string
	SourceKey      string
	EmbeddingModel string
	EmbeddingKind  string
	Attempts       int32
	MaxAttempts    int32
	LeaseToken     string
}

type embeddingInput struct {
	Text             string
	SourceObservedAt *time.Time
	SourceStreamName string
	SourceSensorID   string
	SourceLocationID string
	SourceMAC        string
	Metadata         map[string]any
}

type completionRow struct {
	JobID               int64          `json:"job_id"`
	LeaseToken          string         `json:"lease_token"`
	SourceTable         string         `json:"source_table"`
	SourceKey           string         `json:"source_key"`
	SourceObservedAt    *time.Time     `json:"source_observed_at"`
	SourceStreamName    string         `json:"source_stream_name"`
	SourceSensorID      string         `json:"source_sensor_id"`
	SourceLocationID    string         `json:"source_location_id"`
	SourceMAC           string         `json:"source_mac"`
	EmbeddingModel      string         `json:"embedding_model"`
	EmbeddingKind       string         `json:"embedding_kind"`
	EmbeddingDimensions int            `json:"embedding_dimensions"`
	ContentSHA256       string         `json:"content_sha256"`
	ContentText         string         `json:"content_text"`
	Embedding           string         `json:"embedding"`
	Metadata            map[string]any `json:"metadata"`
}

func StartEmbedder(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, embedder embed.Client, logger zerolog.Logger) {
	if !cfg.EmbedderEnabled {
		logger.Info().Msg("embedded job drainer disabled")
		return
	}
	logger.Warn().Msg("embedded job drainer enabled; vec-worker remains the default embedding processor")
	go func() {
		ticker := time.NewTicker(cfg.EmbeddingPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := drainEmbeddingJobs(ctx, pool, cfg, embedder, logger); err != nil {
					logger.Warn().Err(err).Msg("embedded job drain failed")
				}
			}
		}
	}()
}

func drainEmbeddingJobs(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, embedder embed.Client, logger zerolog.Logger) error {
	if _, err := pool.Exec(ctx, "SELECT vec_enqueue_embedding_jobs($1, $2)", cfg.EmbeddingModel, cfg.EventEmbeddingScope); err != nil {
		return fmt.Errorf("enqueue embedding jobs: %w", err)
	}

	jobs, err := leaseEmbeddingJobs(ctx, pool, cfg.EmbeddingBatchSize)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return nil
	}

	type preparedJob struct {
		job   embeddingJob
		input embeddingInput
	}
	byKind := make(map[string][]preparedJob)
	for _, job := range jobs {
		input, err := buildEmbeddingInput(ctx, pool, job)
		if err != nil {
			logger.Warn().Err(err).Int64("job_id", job.JobID).Str("kind", job.EmbeddingKind).Msg("embedding text build failed")
			if failErr := failEmbeddingJob(ctx, pool, job, err); failErr != nil {
				logger.Warn().Err(failErr).Int64("job_id", job.JobID).Msg("failed to update embedding job failure")
			}
			continue
		}
		byKind[job.EmbeddingKind] = append(byKind[job.EmbeddingKind], preparedJob{job: job, input: input})
	}

	completions := make([]completionRow, 0, len(jobs))
	for kind, group := range byKind {
		texts := make([]string, 0, len(group))
		for _, item := range group {
			texts = append(texts, item.input.Text)
		}
		vectors, err := embedder.Embed(ctx, texts, embed.Kind(kind))
		if err != nil {
			for _, item := range group {
				if failErr := failEmbeddingJob(ctx, pool, item.job, err); failErr != nil {
					logger.Warn().Err(failErr).Int64("job_id", item.job.JobID).Msg("failed to update embedding job failure")
				}
			}
			continue
		}
		if len(vectors) != len(group) {
			err := fmt.Errorf("embedding backend returned %d vectors for %d jobs", len(vectors), len(group))
			for _, item := range group {
				if failErr := failEmbeddingJob(ctx, pool, item.job, err); failErr != nil {
					logger.Warn().Err(failErr).Int64("job_id", item.job.JobID).Msg("failed to update embedding job failure")
				}
			}
			continue
		}
		for i, vector := range vectors {
			if len(vector) != cfg.EmbeddingDimensions {
				err := fmt.Errorf("embedding vector has %d dimensions, expected %d", len(vector), cfg.EmbeddingDimensions)
				if failErr := failEmbeddingJob(ctx, pool, group[i].job, err); failErr != nil {
					logger.Warn().Err(failErr).Int64("job_id", group[i].job.JobID).Msg("failed to update embedding job failure")
				}
				continue
			}
			completions = append(completions, newCompletionRow(group[i].job, group[i].input, vector, cfg.EmbeddingDimensions))
		}
	}

	if len(completions) == 0 {
		return nil
	}
	if err := completeEmbeddingBatch(ctx, pool, completions); err != nil {
		logger.Warn().Err(err).Int("completion_count", len(completions)).Msg("batch embedding completion failed; retrying individually")
		for _, row := range completions {
			if oneErr := completeEmbeddingBatch(ctx, pool, []completionRow{row}); oneErr != nil {
				job := embeddingJob{
					JobID:          row.JobID,
					EmbeddingKind:  row.EmbeddingKind,
					EmbeddingModel: row.EmbeddingModel,
					SourceTable:    row.SourceTable,
					SourceKey:      row.SourceKey,
					LeaseToken:     row.LeaseToken,
					Attempts:       1,
					MaxAttempts:    1,
				}
				if failErr := failEmbeddingJob(ctx, pool, job, oneErr); failErr != nil {
					logger.Warn().Err(failErr).Int64("job_id", row.JobID).Msg("failed to update embedding job after completion error")
				}
			}
		}
	}
	return nil
}

func leaseEmbeddingJobs(ctx context.Context, pool *pgxpool.Pool, batchSize int) ([]embeddingJob, error) {
	rows, err := pool.Query(ctx, `
SELECT job_id, source_table, source_key, embedding_model, embedding_kind, attempts, max_attempts, lease_token
FROM vec_lease_embedding_jobs($1, $2, make_interval(secs => $3))
`, batchSize, embedderWorkerName, 600)
	if err != nil {
		return nil, fmt.Errorf("lease embedding jobs: %w", err)
	}
	defer rows.Close()
	jobs := make([]embeddingJob, 0, batchSize)
	for rows.Next() {
		var job embeddingJob
		if err := rows.Scan(
			&job.JobID,
			&job.SourceTable,
			&job.SourceKey,
			&job.EmbeddingModel,
			&job.EmbeddingKind,
			&job.Attempts,
			&job.MaxAttempts,
			&job.LeaseToken,
		); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func buildEmbeddingInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	switch job.EmbeddingKind {
	case "event":
		return buildEventInput(ctx, pool, job)
	case "device":
		return buildDeviceInput(ctx, pool, job)
	case "behaviour_window":
		return buildBehaviourInput(ctx, pool, job)
	case "frame_sequence":
		return buildSequenceInput(ctx, pool, job)
	case "baseline_profile":
		return buildBaselineInput(ctx, pool, job)
	case "infrastructure_subgraph":
		return buildInfrastructureInput(ctx, pool, job)
	case "timing_profile":
		return buildTimingInput(ctx, pool, job)
	default:
		return embeddingInput{}, fmt.Errorf("unsupported embedding_kind: %s", job.EmbeddingKind)
	}
}

func buildEventInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	var observed pgtype.Timestamptz
	var streamName, sensorID, locationID, sourceMAC string
	var entry searchpkg.AuditEntry
	err := pool.QueryRow(ctx, `
SELECT
  observed_at,
  coalesce(stream_name, ''),
  coalesce(sensor_id, payload->>'sensor_id', ''),
  coalesce(location_id, payload->>'location_id', ''),
  lower(coalesce(source_mac, payload->>'source_mac', '')),
  coalesce(frame_type, payload->>'frame_type', ''),
  coalesce(frame_subtype, payload->>'frame_subtype', ''),
  coalesce(app_protocol, payload->>'app_protocol', ''),
  coalesce(transport_protocol, payload->>'transport_protocol', ''),
  coalesce(security_flags::text, payload->>'security_flags', ''),
  coalesce(dns_query_name, payload->>'dns_query_name', ''),
  coalesce(mdns_name, payload->>'mdns_name', ''),
  coalesce(dhcp_hostname, payload->>'dhcp_hostname', ''),
  coalesce(wps_device_name, payload->>'wps_device_name', ''),
  coalesce(wps_manufacturer, payload->>'wps_manufacturer', ''),
  coalesce(wps_model_name, payload->>'wps_model_name', ''),
  coalesce(ssid, payload->>'ssid', ''),
  coalesce(device_fingerprint, payload->>'device_fingerprint', ''),
  coalesce(handshake_captured::text, payload->>'handshake_captured', ''),
  coalesce(protected::text, payload->>'protected', ''),
  coalesce(channel_number::text, payload->>'channel_number', payload->>'channel', ''),
  coalesce(signal_dbm::text, payload->>'signal_dbm', ''),
  coalesce(retry::text, payload->>'retry', ''),
  coalesce(more_data::text, payload->>'more_data', ''),
  coalesce(power_save::text, payload->>'power_save', '')
FROM sync_events_expanded
WHERE dedupe_key = $1
`, job.SourceKey).Scan(
		&observed,
		&streamName,
		&sensorID,
		&locationID,
		&sourceMAC,
		&entry.FrameType,
		&entry.FrameSubtype,
		&entry.AppProtocol,
		&entry.TransportProtocol,
		&entry.SecurityFlags,
		&entry.DNSQueryName,
		&entry.MDNSName,
		&entry.DHCPHostname,
		&entry.WPSDeviceName,
		&entry.WPSManufacturer,
		&entry.WPSModelName,
		&entry.SSID,
		&entry.DeviceFingerprint,
		&entry.HandshakeCaptured,
		&entry.Protected,
		&entry.ChannelNumber,
		&entry.SignalDBM,
		&entry.Retry,
		&entry.MoreData,
		&entry.PowerSave,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return embeddingInput{}, fmt.Errorf("event source row not found: %s", job.SourceKey)
	}
	if err != nil {
		return embeddingInput{}, fmt.Errorf("event source query: %w", err)
	}
	if observed.Valid {
		entry.ObservedAt = &observed.Time
	}
	return embeddingInput{
		Text:             searchpkg.BuildEventText(entry),
		SourceObservedAt: optionalTime(observed),
		SourceStreamName: streamName,
		SourceSensorID:   sensorID,
		SourceLocationID: locationID,
		SourceMAC:        sourceMAC,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildDeviceInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	var firstSeen, lastSeen pgtype.Timestamptz
	var device searchpkg.Device
	err := pool.QueryRow(ctx, `
SELECT
  d.mac_id,
  coalesce(d.display_name, ''),
  coalesce(d.username, ''),
  coalesce(d.hostname, ''),
  coalesce(d.os_hint, ''),
  coalesce(d.mac_hint, ''),
  d.first_seen,
  d.last_seen,
  coalesce(dic.size, 1)
FROM devices d
LEFT JOIN device_identity_clusters dic ON d.mac_id = ANY(dic.mac_ids)
WHERE d.mac_id = $1
`, strings.ToLower(job.SourceKey)).Scan(
		&device.MACID,
		&device.DisplayName,
		&device.Username,
		&device.Hostname,
		&device.OSHint,
		&device.MACHint,
		&firstSeen,
		&lastSeen,
		&device.ClusterSize,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return embeddingInput{}, fmt.Errorf("device source row not found: %s", job.SourceKey)
	}
	if err != nil {
		return embeddingInput{}, fmt.Errorf("device source query: %w", err)
	}
	if firstSeen.Valid {
		device.FirstSeen = &firstSeen.Time
	}
	if lastSeen.Valid {
		device.LastSeen = &lastSeen.Time
	}
	return embeddingInput{
		Text:             searchpkg.BuildDeviceText(device),
		SourceObservedAt: optionalTime(lastSeen),
		SourceMAC:        device.MACID,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildBehaviourInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	var windowStart, windowEnd pgtype.Timestamptz
	var sensorID, locationID, sourceMAC, embeddingText, textSummary string
	var snapshot searchpkg.BehaviourSnapshot
	err := pool.QueryRow(ctx, `
SELECT
  window_start,
  window_end,
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  lower(coalesce(source_mac, '')),
  event_count,
  protocol_mix::text,
  frame_type_distribution::text,
  coalesce(signal_min_dbm::text, ''),
  coalesce(signal_max_dbm::text, ''),
  coalesce(signal_avg_dbm::text, ''),
  retry_count,
  protected_count,
  unprotected_count,
  unique_bssid_count,
  mac_rotation_indicators::text,
  coalesce(embedding_text, ''),
  coalesce(text_summary, '')
FROM vec_behaviour_snapshots
WHERE snapshot_id::text = $1 OR snapshot_key = $1
`, job.SourceKey).Scan(
		&windowStart,
		&windowEnd,
		&sensorID,
		&locationID,
		&sourceMAC,
		&snapshot.EventCount,
		&snapshot.ProtocolMix,
		&snapshot.FrameTypeDistribution,
		&snapshot.SignalMinDBM,
		&snapshot.SignalMaxDBM,
		&snapshot.SignalAvgDBM,
		&snapshot.RetryCount,
		&snapshot.ProtectedCount,
		&snapshot.UnprotectedCount,
		&snapshot.UniqueBSSIDCount,
		&snapshot.MacRotationIndicators,
		&embeddingText,
		&textSummary,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return embeddingInput{}, fmt.Errorf("behaviour_window source row not found: %s", job.SourceKey)
	}
	if err != nil {
		return embeddingInput{}, fmt.Errorf("behaviour_window source query: %w", err)
	}
	text := prebuiltKindText("behaviour_window", embeddingText, optionalTime(windowStart))
	if text == "" {
		text = prebuiltKindText("behaviour_window", textSummary, optionalTime(windowStart))
	}
	if text == "" {
		text = searchpkg.BuildBehaviourText(snapshot)
	}
	if epm := eventsPerMinute(snapshot.EventCount, optionalTime(windowStart), optionalTime(windowEnd)); epm > 0 && !strings.Contains(text, "events_per_minute:") {
		text += fmt.Sprintf("\nevents_per_minute: %.1f", epm)
	}
	return embeddingInput{
		Text:             text,
		SourceObservedAt: optionalTime(windowStart),
		SourceSensorID:   sensorID,
		SourceLocationID: locationID,
		SourceMAC:        sourceMAC,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildSequenceInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	var windowStart, windowEnd pgtype.Timestamptz
	var sourceMAC, sensorID, locationID, semanticTokens, sequenceTokens string
	var frameCount int64
	err := pool.QueryRow(ctx, `
SELECT
  coalesce(source_mac, ''),
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  window_start,
  window_end,
  sequence_tokens,
  coalesce(semantic_tokens, ''),
  frame_count
FROM vec_frame_sequences
WHERE session_key = $1
`, job.SourceKey).Scan(
		&sourceMAC,
		&sensorID,
		&locationID,
		&windowStart,
		&windowEnd,
		&sequenceTokens,
		&semanticTokens,
		&frameCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return embeddingInput{}, fmt.Errorf("frame_sequence source row not found: %s", job.SourceKey)
	}
	if err != nil {
		return embeddingInput{}, fmt.Errorf("frame_sequence source query: %w", err)
	}
	tokenSource := strings.TrimSpace(semanticTokens)
	if tokenSource == "" {
		tokenSource = sequenceTokens
	}
	lines := []string{"kind: frame_sequence", "tokens: " + truncateWords(tokenSource, 368)}
	if windowStart.Valid && windowEnd.Valid {
		lines = append(lines, fmt.Sprintf("window_secs: %d", int64(windowEnd.Time.Sub(windowStart.Time).Seconds())))
	}
	if score, err := searchpkg.ScoreSequence(ctx, pool, strings.Fields(sequenceTokens)); err == nil && score != 0 {
		lines = append(lines, fmt.Sprintf("log_prob: %.6f", score))
	}
	lines = append(lines, fmt.Sprintf("frame_count: %d", frameCount))
	return embeddingInput{
		Text:             strings.Join(lines, "\n"),
		SourceObservedAt: optionalTime(windowStart),
		SourceSensorID:   sensorID,
		SourceLocationID: locationID,
		SourceMAC:        sourceMAC,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildBaselineInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	rows, err := pool.Query(ctx, `
SELECT metric, p5::text, p50::text, p95::text, updated_at
FROM vec_baseline_profiles
WHERE bssid = $1
ORDER BY metric
`, job.SourceKey)
	if err != nil {
		return embeddingInput{}, fmt.Errorf("baseline_profile source query: %w", err)
	}
	defer rows.Close()

	lines := []string{"kind: baseline_profile", "bssid: " + job.SourceKey}
	var lastSeen *time.Time
	count := 0
	for rows.Next() {
		var metric, p5, p50, p95 string
		var updated pgtype.Timestamptz
		if err := rows.Scan(&metric, &p5, &p50, &p95, &updated); err != nil {
			return embeddingInput{}, err
		}
		if count < 61 {
			lines = append(lines, fmt.Sprintf("metric: %s p5: %s p50: %s p95: %s", metric, p5, p50, p95))
		}
		if updated.Valid && (lastSeen == nil || updated.Time.After(*lastSeen)) {
			t := updated.Time
			lastSeen = &t
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return embeddingInput{}, err
	}
	if count == 0 {
		return embeddingInput{}, fmt.Errorf("baseline_profile source row not found: %s", job.SourceKey)
	}
	if count > 61 {
		lines = append(lines, fmt.Sprintf("(+%d metrics truncated)", count-61))
	}
	return embeddingInput{
		Text:             strings.Join(lines, "\n"),
		SourceObservedAt: lastSeen,
		SourceMAC:        job.SourceKey,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildInfrastructureInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	rows, err := pool.Query(ctx, `
SELECT node_a, node_a_type, node_b, node_b_type, edge_type, weight::text, last_seen
FROM vec_infrastructure_graph
WHERE node_a = $1 OR node_b = $1
ORDER BY weight DESC, last_seen DESC
`, job.SourceKey)
	if err != nil {
		return embeddingInput{}, fmt.Errorf("infrastructure_subgraph source query: %w", err)
	}
	defer rows.Close()

	edgeCounts := map[string]int{}
	clients := map[string]struct{}{}
	ssids := map[string]struct{}{}
	vendors := map[string]struct{}{}
	var lastSeen *time.Time
	rowCount := 0
	for rows.Next() {
		var nodeA, nodeAType, nodeB, nodeBType, edgeType, weight string
		var seen pgtype.Timestamptz
		if err := rows.Scan(&nodeA, &nodeAType, &nodeB, &nodeBType, &edgeType, &weight, &seen); err != nil {
			return embeddingInput{}, err
		}
		edgeCounts[edgeType]++
		neighbor, neighborType := nodeB, nodeBType
		if nodeB == job.SourceKey {
			neighbor, neighborType = nodeA, nodeAType
		}
		switch {
		case neighborType == "client_mac" && edgeType == "association":
			clients[neighbor] = struct{}{}
		case neighborType == "ssid" && edgeType == "probe_target":
			ssids[neighbor] = struct{}{}
		case neighborType == "vendor":
			vendors[neighbor] = struct{}{}
		}
		if seen.Valid && (lastSeen == nil || seen.Time.After(*lastSeen)) {
			t := seen.Time
			lastSeen = &t
		}
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return embeddingInput{}, err
	}
	if rowCount == 0 {
		return embeddingInput{}, fmt.Errorf("infrastructure_subgraph source row not found: %s", job.SourceKey)
	}
	edgeParts := make([]string, 0, len(edgeCounts))
	for edgeType, count := range edgeCounts {
		edgeParts = append(edgeParts, fmt.Sprintf("%s:%d", edgeType, count))
	}
	sort.Strings(edgeParts)
	lines := []string{"kind: infrastructure_subgraph", "center: " + job.SourceKey}
	if len(ssids) > 0 {
		lines = append(lines, fmt.Sprintf("ssid: %d", len(ssids)))
	}
	if len(clients) > 0 {
		lines = append(lines, fmt.Sprintf("clients: %d", len(clients)))
	}
	if len(vendors) > 0 {
		lines = append(lines, fmt.Sprintf("vendor_diversity: %d", len(vendors)))
	}
	lines = append(lines, "edges: "+strings.Join(edgeParts, ","))
	return embeddingInput{
		Text:             strings.Join(lines, "\n"),
		SourceObservedAt: lastSeen,
		SourceMAC:        job.SourceKey,
		Metadata:         baseMetadata(job),
	}, nil
}

func buildTimingInput(ctx context.Context, pool *pgxpool.Pool, job embeddingJob) (embeddingInput, error) {
	var windowStart pgtype.Timestamptz
	var sourceMAC, sensorID, locationID, embeddingText string
	var tsftP50, tsftP95, tsftJitter, wallP50, wallJitter, beaconMedian, beaconJitter string
	err := pool.QueryRow(ctx, `
SELECT
  lower(source_mac),
  coalesce(sensor_id, ''),
  coalesce(location_id, ''),
  window_start,
  coalesce(tsft_p50_us::text, ''),
  coalesce(tsft_p95_us::text, ''),
  coalesce(tsft_jitter::text, ''),
  coalesce(wall_p50_ms::text, ''),
  coalesce(wall_jitter_ms::text, ''),
  coalesce(beacon_interval_median_ms::text, ''),
  coalesce(beacon_jitter_ms::text, ''),
  coalesce(embedding_text, '')
FROM vec_timing_profiles
WHERE profile_id::text = $1 OR profile_key = $1
`, job.SourceKey).Scan(
		&sourceMAC,
		&sensorID,
		&locationID,
		&windowStart,
		&tsftP50,
		&tsftP95,
		&tsftJitter,
		&wallP50,
		&wallJitter,
		&beaconMedian,
		&beaconJitter,
		&embeddingText,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return embeddingInput{}, fmt.Errorf("timing_profile source row not found: %s", job.SourceKey)
	}
	if err != nil {
		return embeddingInput{}, fmt.Errorf("timing_profile source query: %w", err)
	}
	text := prebuiltKindText("timing_profile", embeddingText, optionalTime(windowStart))
	if text == "" {
		lines := []string{"kind: timing_profile"}
		appendTemporalLines(&lines, optionalTime(windowStart))
		appendKV(&lines, "tsft_p50_us", tsftP50)
		appendKV(&lines, "tsft_p95_us", tsftP95)
		appendKV(&lines, "tsft_jitter", tsftJitter)
		appendKV(&lines, "wall_p50_ms", wallP50)
		appendKV(&lines, "wall_jitter_ms", wallJitter)
		appendKV(&lines, "beacon_interval_ms", beaconMedian)
		appendKV(&lines, "beacon_jitter_ms", beaconJitter)
		text = strings.Join(lines, "\n")
	}
	return embeddingInput{
		Text:             text,
		SourceObservedAt: optionalTime(windowStart),
		SourceSensorID:   sensorID,
		SourceLocationID: locationID,
		SourceMAC:        sourceMAC,
		Metadata:         baseMetadata(job),
	}, nil
}

func completeEmbeddingBatch(ctx context.Context, pool *pgxpool.Pool, rows []completionRow) error {
	payload, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	var completed int64
	if err := pool.QueryRow(ctx, "SELECT vec_complete_embedding_batch($1::jsonb)", string(payload)).Scan(&completed); err != nil {
		return err
	}
	if completed != int64(len(rows)) {
		return fmt.Errorf("completed %d of %d embedding jobs", completed, len(rows))
	}
	return nil
}

func failEmbeddingJob(ctx context.Context, pool *pgxpool.Pool, job embeddingJob, cause error) error {
	backoff := int32(math.Max(10, math.Min(300, float64(job.Attempts*10))))
	_, err := pool.Exec(ctx, `
UPDATE vec_embedding_jobs
SET status = CASE WHEN $2 >= max_attempts THEN 'failed' ELSE 'pending' END,
    lease_token = NULL,
    leased_at = NULL,
    locked_by = NULL,
    last_error = $1,
    due_at = now() + make_interval(secs => $3),
    updated_at = now()
WHERE job_id = $4
  AND lease_token IS NOT DISTINCT FROM $5
`, truncateError(cause), job.Attempts, backoff, job.JobID, job.LeaseToken)
	return err
}

func newCompletionRow(job embeddingJob, input embeddingInput, vector []float32, dimensions int) completionRow {
	return completionRow{
		JobID:               job.JobID,
		LeaseToken:          job.LeaseToken,
		SourceTable:         job.SourceTable,
		SourceKey:           job.SourceKey,
		SourceObservedAt:    input.SourceObservedAt,
		SourceStreamName:    input.SourceStreamName,
		SourceSensorID:      input.SourceSensorID,
		SourceLocationID:    input.SourceLocationID,
		SourceMAC:           input.SourceMAC,
		EmbeddingModel:      job.EmbeddingModel,
		EmbeddingKind:       job.EmbeddingKind,
		EmbeddingDimensions: dimensions,
		ContentSHA256:       contentSHA256(input.Text),
		ContentText:         input.Text,
		Embedding:           searchpkg.VectorLiteral(vector),
		Metadata:            input.Metadata,
	}
}

func baseMetadata(job embeddingJob) map[string]any {
	return map[string]any{
		"builder":        "atheros-search",
		"source_table":   job.SourceTable,
		"source_key":     job.SourceKey,
		"embedding_kind": job.EmbeddingKind,
	}
}

func contentSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func optionalTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func prebuiltKindText(kind, text string, observed *time.Time) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	lines := []string{"kind: " + kind}
	appendTemporalLines(&lines, observed)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "kind:") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func appendTemporalLines(lines *[]string, t *time.Time) {
	if t == nil {
		return
	}
	weekday := strings.ToLower(t.Weekday().String())
	appendKV(lines, "hour_of_day", fmt.Sprintf("%02d", t.Hour()))
	appendKV(lines, "day_of_week", weekday)
	appendKV(lines, "is_weekend", fmt.Sprintf("%t", t.Weekday() == time.Saturday || t.Weekday() == time.Sunday))
	appendKV(lines, "is_business_hours", fmt.Sprintf("%t", t.Hour() >= 9 && t.Hour() < 17))
}

func appendKV(lines *[]string, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "null") {
		return
	}
	*lines = append(*lines, key+": "+value)
}

func eventsPerMinute(count int64, start, end *time.Time) float64 {
	if start == nil || end == nil || !end.After(*start) {
		return 0
	}
	minutes := end.Sub(*start).Minutes()
	if minutes <= 0 {
		return 0
	}
	return float64(count) / minutes
}

func truncateWords(text string, maxWords int) string {
	words := strings.Fields(text)
	if len(words) <= maxWords {
		return text
	}
	return strings.Join(words[:maxWords], " ") + fmt.Sprintf(" (+%d truncated)", len(words)-maxWords)
}

func truncateError(err error) string {
	message := err.Error()
	if len(message) <= 2048 {
		return message
	}
	i := 2048
	for i > 0 && !utf8.RuneStart(message[i]) {
		i--
	}
	return message[:i]
}
