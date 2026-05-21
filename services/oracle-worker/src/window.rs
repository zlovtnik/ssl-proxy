use std::{
    future::Future,
    time::{Duration, Instant},
};

use rdkafka::{consumer::StreamConsumer, Message};

use crate::worker::OracleLoad;

#[derive(Clone, Debug)]
pub(crate) struct CommitTarget {
    pub(crate) topic: String,
    pub(crate) partition: i32,
    pub(crate) offset: i64,
}

pub(crate) struct CollectedMessage {
    pub(crate) commit_target: CommitTarget,
    pub(crate) load: Result<OracleLoad, serde_json::Error>,
    pub(crate) payload_bytes: usize,
}

pub(crate) struct WindowSummary {
    pub(crate) collected: usize,
    pub(crate) poison: usize,
    pub(crate) elapsed_collect_ms: u128,
}

struct RawMessage {
    commit_target: CommitTarget,
    payload: Vec<u8>,
}

pub(crate) async fn collect(
    consumer: &StreamConsumer,
    max_messages: usize,
    duration: Duration,
) -> (Vec<CollectedMessage>, WindowSummary) {
    collect_records(max_messages, duration, || async {
        let message = consumer.recv().await.ok()?;
        let payload = message.payload().unwrap_or_default().to_vec();
        Some(RawMessage {
            commit_target: CommitTarget {
                topic: message.topic().to_string(),
                partition: message.partition(),
                offset: message.offset(),
            },
            payload,
        })
    })
    .await
}

async fn collect_records<Recv, Fut>(
    max_messages: usize,
    duration: Duration,
    mut recv: Recv,
) -> (Vec<CollectedMessage>, WindowSummary)
where
    Recv: FnMut() -> Fut,
    Fut: Future<Output = Option<RawMessage>>,
{
    let started = Instant::now();
    let deadline = started.checked_add(duration).unwrap_or(started);
    let mut messages = Vec::with_capacity(max_messages);
    let mut poison = 0;

    while messages.len() < max_messages {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        let raw = match tokio::time::timeout(remaining, recv()).await {
            Ok(Some(raw)) => raw,
            Ok(None) | Err(_) => break,
        };
        let payload_bytes = raw.payload.len();
        let load = serde_json::from_slice::<OracleLoad>(&raw.payload);
        if load.is_err() {
            poison += 1;
        }
        messages.push(CollectedMessage {
            commit_target: raw.commit_target,
            load,
            payload_bytes,
        });
    }

    let summary = WindowSummary {
        collected: messages.len(),
        poison,
        elapsed_collect_ms: started.elapsed().as_millis(),
    };
    (messages, summary)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicI64, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use super::{collect_records, CommitTarget, RawMessage};
    use crate::worker::OracleLoad;

    #[tokio::test]
    async fn collect_stops_at_deadline() {
        let next_offset = Arc::new(AtomicI64::new(0));
        let (messages, summary) = collect_records(200, Duration::from_millis(150), || {
            let next_offset = Arc::clone(&next_offset);
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let offset = next_offset.fetch_add(1, Ordering::SeqCst);
                Some(raw_message(
                    offset,
                    valid_payload(&format!("batch-{offset}")),
                ))
            }
        })
        .await;

        assert!(
            (7..=8).contains(&messages.len()),
            "expected 7-8 messages, got {}",
            messages.len()
        );
        assert_eq!(summary.collected, messages.len());
        assert_eq!(summary.poison, 0);
        assert!(summary.elapsed_collect_ms >= 140);
    }

    #[tokio::test]
    async fn collect_stops_at_max_messages() {
        let next_offset = Arc::new(AtomicI64::new(0));
        let (messages, summary) = collect_records(3, Duration::from_secs(60), || {
            let next_offset = Arc::clone(&next_offset);
            async move {
                let offset = next_offset.fetch_add(1, Ordering::SeqCst);
                Some(raw_message(
                    offset,
                    valid_payload(&format!("batch-{offset}")),
                ))
            }
        })
        .await;

        assert_eq!(messages.len(), 3);
        assert_eq!(summary.collected, 3);
        assert_eq!(summary.poison, 0);
        assert!(summary.elapsed_collect_ms < 1_000);
    }

    #[tokio::test]
    async fn collect_returns_empty_cleanly() {
        let (messages, summary) = collect_records(10, Duration::from_millis(25), || async {
            std::future::pending::<Option<RawMessage>>().await
        })
        .await;

        assert!(messages.is_empty());
        assert_eq!(summary.collected, 0);
        assert_eq!(summary.poison, 0);
        assert!(summary.elapsed_collect_ms >= 20);
    }

    #[tokio::test]
    async fn collect_marks_poison_correctly() {
        let records = Arc::new(Mutex::new(VecDeque::from([
            raw_message(0, valid_payload("batch-ok")),
            raw_message(1, b"{not-json".to_vec()),
        ])));
        let (messages, summary) = collect_records(10, Duration::from_secs(1), || {
            let records = Arc::clone(&records);
            async move { records.lock().unwrap().pop_front() }
        })
        .await;

        assert_eq!(messages.len(), 2);
        assert!(messages[0].load.is_ok());
        assert!(messages[1].load.is_err());
        assert_eq!(summary.collected, 2);
        assert_eq!(summary.poison, 1);
    }

    fn raw_message(offset: i64, payload: Vec<u8>) -> RawMessage {
        RawMessage {
            commit_target: CommitTarget {
                topic: "sync.oracle.load".to_string(),
                partition: 0,
                offset,
            },
            payload,
        }
    }

    fn valid_payload(batch_id: &str) -> Vec<u8> {
        serde_json::to_vec(&OracleLoad {
            job_id: "job-1".to_string(),
            batch_id: batch_id.to_string(),
            batch_no: 1,
            stream_name: "proxy.events".to_string(),
            payload_ref: "inline://json/e30".to_string(),
            cursor_start: "0".to_string(),
            cursor_end: "1".to_string(),
            attempt: 1,
        })
        .unwrap()
    }
}
