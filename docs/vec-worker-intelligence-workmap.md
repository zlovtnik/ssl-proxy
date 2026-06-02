# vec-worker: Intelligence Workmap

## From Noisy Deduplication → Actionable Device Intelligence

**Status as of 2026-05-26**

> This is a historical planning document. It was moved from
> `services/vec-worker/README.md` to keep the README focused on
> reference documentation. Some tracks may have been implemented
> (partially or fully) since this was written.

The similarity pipeline is working at the event level (cosine distance 0.017–0.035 on
`event_event` pairs is real signal). The problems are architectural: the things that
matter most — device identity across MACs, frame sequence anomaly scoring, and the
`v_device_repetition_score` view — are either empty or producing noise the rest of the
stack can't consume. This document is a bottom-up fix plan with no repetition and
no wishful thinking.

---

## Why `v_device_repetition_score` Is Empty

This is the most important thing to fix first, because every downstream alert and
dashboard depends on it.

The view queries `vec_similarity_pairs` for `event_event` pairs and groups by
`source_mac`. The data above shows `event_event` pairs *do exist*, all associated
with MAC `30:93:bc:81:b3:de`. But the view is empty. The reason is almost certainly
one of:

1. **`left_source_mac` / `right_source_mac` are NULL** in the similarity pairs rows,
   even though the events themselves have `source_mac` populated. The builder uses
   `COALESCE(sensor_id, payload->>'sensor_id')` for sensor but the MAC fields come from
   `sync_events_expanded.source_mac` — if that column was null at embedding time, the
   similarity pair stored a null MAC and the `GROUP BY source_mac` collapses to nothing.

2. **The materialized view refresh is failing silently** because
   `REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score` requires a unique
   index on `source_mac`. If that index was added after the first refresh created the
   view without it, concurrent refresh throws an error that `run_alert_sweep` swallows
   with a `warn!` and continues.

---

## Device Identity Across Multiple MACs

This is the core intelligence gap. A device using MAC randomization (all those
`a2:`, `6a:`, `be:`, `c6:` prefixed locally-administered MACs in the behaviour
window data) shows up as dozens of independent "devices" when it's one physical
device.

### Track 1 — Populate `mac_rotation_indicators` correctly

The field should contain signals that let the model (and similarity search) recognize
rotation patterns.

### Track 2 — Cross-MAC device grouping table

The vector similarity approach (embedding behaviour windows and finding near-duplicates)
is the right direction, but the output needs a concrete grouping table, not just pairs.
The `device_identity_clusters` table was added in `sql/tables/012_device_identity_clusters.sql`.

### Track 3 — Surface clusters in the Rust worker

In `text_builder.rs`, the `build_device` function should also pull from
`device_identity_clusters` and include the cluster context.

---

## Frame Sequences — Making Them Actually Useful

### Track 4 — Normalize sequence token vocabulary

The transition model is only useful if the token vocabulary is stable and small.

### Track 5 — Alert threshold calibration

The current threshold of `-15` is too tight for the normalized vocabulary.

---

## What Makes the Similarity Pairs Actually Valuable

### Track 6 — Distinguish normal repetition from attack repetition

The near-duplicate sweep marks everything above the threshold as a
`near_duplicate_cluster` alert. But an AP sending beacons every 100ms is expected.

### Track 7 — `high_risk_ap` score decomposition

Alert metadata decomposition is more useful than the composite alone.

---

## Implementation Order

| # | Track | Change | Risk | Expected outcome |
|---|-------|--------|------|-----------------|
| 1 | Diagnostic | Run the 4 diagnostic queries for `v_device_repetition_score` | None | Identify whether MAC-null or missing index is the root cause |
| 2 | Fix A or B | Fix MAC propagation **or** create unique index | Low | `v_device_repetition_score` becomes non-empty |
| 3 | Frame seqs | Apply prior workmap Fix 1–4 (rename, cron, column COALESCE, null-safe) | Medium | `vec_frame_sequences` starts populating |
| 4 | Track 4 | Normalize frame sequence vocabulary to 13-token set | Low | Transition model scores become meaningful |
| 5 | Track 5 | Rebuild transition model, calibrate alert threshold | None | Rogue cluster alerts become reliable |
| 6 | Track 1 | Improve `mac_rotation_indicators` in snapshot builder | Low | Behaviour window embeddings carry rotation signal |
| 7 | Track 2 | Add `device_identity_clusters` table and function | Medium | MAC-rotated devices tracked as single identity |
| 8 | Track 3 | Surface cluster context in device text builder | Low | Device embeddings include cluster-size signal |
| 9 | Track 6 | Filter near-duplicate alerts by LA-MAC / cross-MAC | Low | Eliminates AP beacon noise from alerts |
| 10 | Track 7 | Populate `explanation_text` in high-risk AP alerts | Low | Alert metadata becomes actionable |