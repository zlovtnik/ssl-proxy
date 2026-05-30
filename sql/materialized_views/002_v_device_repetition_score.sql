-- object: v_device_repetition_score
-- folder: materialized_views
-- depends_on: vec_similarity_pairs
-- vec similarity foundation end
-- V019: Create v_device_repetition_score view
--
-- Provides a queryable surface for near-duplicate detection in vec_similarity_pairs.
-- Since a pair has a left and right side, we union both sides to count how many
-- times a device appears as a near-duplicate participant.

CREATE MATERIALIZED VIEW IF NOT EXISTS v_device_repetition_score AS
WITH device_pairs AS (
    -- Left side: device is the left member of the pair
    SELECT
        p.left_source_mac AS source_mac,
        p.cosine_distance,
        p.left_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs p
    WHERE p.pair_kind = 'event_event'
      AND p.cosine_distance < 0.05
      AND p.left_source_mac IS NOT NULL

    UNION ALL

    -- Right side: device is the right member of the pair
    SELECT
        p.right_source_mac AS source_mac,
        p.cosine_distance,
        p.right_embedding_id AS embedding_id,
        p.computed_at
    FROM vec_similarity_pairs p
    WHERE p.pair_kind = 'event_event'
      AND p.cosine_distance < 0.05
      AND p.right_source_mac IS NOT NULL
)
SELECT
    source_mac,
    COUNT(*) AS near_duplicate_pairs,
    MIN(cosine_distance) AS min_distance,
    AVG(cosine_distance) AS avg_distance,
    COUNT(DISTINCT embedding_id) AS unique_events_implicated
FROM device_pairs
WHERE computed_at >= NOW() - INTERVAL '7 days'
GROUP BY source_mac
ORDER BY near_duplicate_pairs DESC;

COMMENT ON MATERIALIZED VIEW v_device_repetition_score IS
  'Daily device repetition scores from near-duplicate event_event pairs in vec_similarity_pairs (cosine_distance < 0.05). Refresh with REFRESH MATERIALIZED VIEW CONCURRENTLY.';
