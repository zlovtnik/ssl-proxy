
use super::*;

fn result(
    rows_leased: usize,
    drained_to_empty: bool,
    max_drain_batches_reached: bool,
) -> RunOnceResult {
    RunOnceResult {
        processed: rows_leased,
        permanent_failures: 0,
        rows_leased,
        drain_batches: usize::from(rows_leased > 0),
        drained_to_empty,
        max_drain_batches_reached,
        drain_ms: 1,
        kind_stats: BTreeMap::new(),
    }
}

fn test_job(job_id: i64, kind: &str) -> EmbeddingJob {
    let now = chrono::Utc::now();
    EmbeddingJob {
        job_id,
        source_table: "test_source".to_string(),
        source_key: job_id.to_string(),
        embedding_model: "test-model".to_string(),
        embedding_kind: kind.to_string(),
        status: "leased".to_string(),
        priority: 10,
        attempts: 1,
        max_attempts: 5,
        lease_token: None,
        leased_at: None,
        locked_by: None,
        due_at: now,
        content_sha256: None,
        last_error: None,
        completed_at: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn drain_continues_after_successful_full_batch_without_cap() {
    assert_eq!(drain_decision(64, 1, 0), DrainDecision::Continue);
    assert_eq!(
        loop_action_after_success(false, &result(64, false, false)),
        LoopAction::ContinueImmediately
    );
}

#[test]
fn drain_sleeps_only_after_empty_lease() {
    assert_eq!(drain_decision(0, 3, 0), DrainDecision::Empty);
    assert_eq!(
        loop_action_after_success(false, &result(0, true, false)),
        LoopAction::SleepIdle
    );
    assert_eq!(
        loop_action_after_success(false, &result(64, false, true)),
        LoopAction::ContinueImmediately
    );
}

#[test]
fn once_mode_exits_after_drain_cycle() {
    assert_eq!(
        loop_action_after_success(true, &result(128, true, false)),
        LoopAction::ExitOnce
    );
}

#[test]
fn max_drain_batches_yields_without_idle_sleep() {
    assert_eq!(drain_decision(64, 2, 2), DrainDecision::MaxBatchesReached);
    assert_eq!(
        loop_action_after_success(false, &result(128, false, true)),
        LoopAction::ContinueImmediately
    );
}

#[test]
fn progress_heartbeat_is_requested_after_each_nonempty_chunk() {
    assert!(should_mark_progress_heartbeat(1, 0));
    assert!(should_mark_progress_heartbeat(0, 1));
    assert!(!should_mark_progress_heartbeat(0, 0));
}

#[test]
fn kind_stats_merge_leased_completed_and_failed_counts() {
    let jobs = vec![
        test_job(1, "event"),
        test_job(2, "event"),
        test_job(3, "frame_sequence"),
    ];
    let mut stats = BTreeMap::new();
    add_leased_jobs(&mut stats, &jobs);

    let mut process = ProcessJobsResult::default();
    process.completed_by_kind.insert("event".to_string(), 1);
    process
        .completed_by_kind
        .insert("frame_sequence".to_string(), 1);
    process.failed_by_kind.insert("event".to_string(), 1);
    process
        .permanent_failed_by_kind
        .insert("event".to_string(), 1);
    add_process_stats(&mut stats, &process);

    assert_eq!(stats["event"].leased, 2);
    assert_eq!(stats["event"].completed, 1);
    assert_eq!(stats["event"].failed, 1);
    assert_eq!(stats["event"].permanent_failed, 1);
    assert_eq!(stats["frame_sequence"].leased, 1);
    assert_eq!(stats["frame_sequence"].completed, 1);
}

#[tokio::test]
async fn db_timeout_returns_retryable_worker_error() {
    let err = with_db_timeout(Duration::from_millis(1), "lease_jobs", async {
        tokio::time::sleep(Duration::from_millis(25)).await;
        Ok::<_, sqlx::Error>(())
    })
    .await
    .expect_err("timeout should return an error");

    match err {
        WorkerError::DbTimeout {
            operation,
            timeout_ms,
        } => {
            assert_eq!(operation, "lease_jobs");
            assert_eq!(timeout_ms, 1);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn db_pressure_errors_skip_fallback() {
    assert!(is_db_pressure_error(&WorkerError::DbTimeout {
        operation: "complete_embedding_batch",
        timeout_ms: 30_000,
    }));
    assert!(is_db_pressure_error(&WorkerError::Database(
        sqlx::Error::PoolTimedOut,
    )));
}
