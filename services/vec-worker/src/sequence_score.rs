//! Frame-sequence scoring for the vector worker.
//!
//! This mirrors the Postgres `vec_score_sequence(text[])` function without
//! issuing one SQL call per sequence.

use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

const DEFAULT_VOCAB_SIZE: usize = 16;

#[derive(Debug, sqlx::FromRow)]
struct TransitionRow {
    prev_token: String,
    next_token: String,
    count: i64,
}

#[derive(Clone, Debug, Default)]
pub struct SequenceScorer {
    counts: HashMap<(String, String), i64>,
    totals: HashMap<String, i64>,
    vocab_size: usize,
}

impl SequenceScorer {
    pub fn from_rows<I>(rows: I) -> Self
    where
        I: IntoIterator<Item = (String, String, i64)>,
    {
        let mut counts = HashMap::new();
        let mut totals = HashMap::new();
        let mut vocab = HashSet::new();

        for (prev, next, count) in rows {
            let safe_count = count.max(0);
            vocab.insert(prev.clone());
            vocab.insert(next.clone());
            *totals.entry(prev.clone()).or_insert(0) += safe_count;
            counts.insert((prev, next), safe_count);
        }

        let vocab_size = if vocab.is_empty() {
            DEFAULT_VOCAB_SIZE
        } else {
            vocab.len()
        };

        Self {
            counts,
            totals,
            vocab_size,
        }
    }

    pub fn score_text(&self, sequence_tokens: &str) -> f64 {
        let tokens: Vec<&str> = sequence_tokens.split_whitespace().collect();
        self.score_tokens(&tokens)
    }

    pub fn score_tokens(&self, tokens: &[&str]) -> f64 {
        if tokens.len() < 2 {
            return 0.0;
        }

        let vocab_size = self.vocab_size as f64;
        let mut log_prob = 0.0;

        for pair in tokens.windows(2) {
            let prev = pair[0];
            let next = pair[1];
            let total = self.totals.get(prev).copied().unwrap_or(0);

            let probability = if total <= 0 {
                1.0 / vocab_size
            } else {
                let count = self
                    .counts
                    .get(&(prev.to_string(), next.to_string()))
                    .copied()
                    .unwrap_or(0);
                (count as f64 + 1.0) / (total as f64 + vocab_size)
            };

            log_prob += probability.log2();
        }

        log_prob
    }
}

pub async fn load_frame_sequence_scorer(pool: &PgPool) -> Result<SequenceScorer, sqlx::Error> {
    let rows = sqlx::query_as::<_, TransitionRow>(
        r#"
        SELECT prev_token, next_token, count
        FROM vec_transition_model
        WHERE embedding_kind = 'frame_sequence'
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(SequenceScorer::from_rows(
        rows.into_iter()
            .map(|row| (row.prev_token, row.next_token, row.count)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scorer() -> SequenceScorer {
        SequenceScorer::from_rows(vec![
            ("AUTH".to_string(), "ASSOC_REQ".to_string(), 3),
            ("AUTH".to_string(), "DEAUTH".to_string(), 1),
            ("ASSOC_REQ".to_string(), "EAPOL".to_string(), 2),
        ])
    }

    #[test]
    fn empty_and_short_sequences_score_zero() {
        let scorer = scorer();
        assert_eq!(scorer.score_tokens(&[]), 0.0);
        assert_eq!(scorer.score_tokens(&["AUTH"]), 0.0);
    }

    #[test]
    fn scores_known_bigram_with_laplace_smoothing() {
        let scorer = scorer();
        let score = scorer.score_tokens(&["AUTH", "ASSOC_REQ"]);
        let expected = ((3.0_f64 + 1.0) / (4.0 + 4.0)).log2();
        assert!((score - expected).abs() < 0.000001);
    }

    #[test]
    fn scores_unseen_bigram_under_known_prefix() {
        let scorer = scorer();
        let score = scorer.score_tokens(&["AUTH", "PROBE_REQ"]);
        let expected = (1.0_f64 / (4.0 + 4.0)).log2();
        assert!((score - expected).abs() < 0.000001);
    }

    #[test]
    fn unknown_prefix_uses_uniform_vocab_probability() {
        let scorer = scorer();
        let score = scorer.score_tokens(&["PROBE_REQ", "AUTH"]);
        let expected = (1.0_f64 / 4.0).log2();
        assert!((score - expected).abs() < 0.000001);
    }

    #[test]
    fn empty_model_uses_default_vocab_size() {
        let scorer = SequenceScorer::from_rows(Vec::new());
        let score = scorer.score_tokens(&["A", "B"]);
        let expected = (1.0_f64 / DEFAULT_VOCAB_SIZE as f64).log2();
        assert!((score - expected).abs() < 0.000001);
    }
}
