
use std::{sync::Arc, time::Duration};

use tokio::{sync::Semaphore, task::JoinSet};

use super::{window_complete_log_lines, CommitTarget, OrderedCommitTracker};

#[test]
fn ordered_commit_tracker_waits_for_lower_offset() {
    let mut tracker = OrderedCommitTracker::default();
    let first = commit_target(2, 41);
    let second = commit_target(2, 42);
    tracker.mark_started(&first);
    tracker.mark_started(&second);

    assert_eq!(tracker.mark_completed(&second).unwrap(), None);

    let ready = tracker.mark_completed(&first).unwrap().unwrap();
    assert_eq!(ready.partition, 2);
    assert_eq!(ready.next_offset, 43);
}

#[test]
fn ordered_commit_tracker_tracks_partitions_independently() {
    let mut tracker = OrderedCommitTracker::default();
    let partition_0 = commit_target(0, 10);
    let partition_1 = commit_target(1, 99);
    tracker.mark_started(&partition_0);
    tracker.mark_started(&partition_1);

    let ready = tracker.mark_completed(&partition_1).unwrap().unwrap();
    assert_eq!(ready.partition, 1);
    assert_eq!(ready.next_offset, 100);

    let ready = tracker.mark_completed(&partition_0).unwrap().unwrap();
    assert_eq!(ready.partition, 0);
    assert_eq!(ready.next_offset, 11);
}

#[test]
fn ordered_commit_tracker_rejects_offset_overflow() {
    let mut tracker = OrderedCommitTracker::default();
    let target = commit_target(0, i64::MAX);
    tracker.mark_started(&target);

    assert!(tracker.mark_completed(&target).is_err());
}

#[tokio::test]
async fn window_overrun_log_fires_when_tasks_exceed_budget() {
    let started = std::time::Instant::now();
    let semaphore = Arc::new(Semaphore::new(1));
    let mut join_set = JoinSet::new();

    for _ in 0..3 {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        join_set.spawn(async move {
            let _permit = permit;
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
    }

    while join_set.join_next().await.is_some() {}

    let lines = window_complete_log_lines(
        7,
        started.elapsed().as_millis(),
        Duration::from_millis(10),
        0,
        3,
    );
    let overrun = lines.overrun.expect("expected overrun log line");
    assert!(overrun.contains("event=window_overrun"));
    assert!(overrun.contains("window_no=7"));
    assert!(overrun.contains("over_budget_ms="));
}

fn commit_target(partition: i32, offset: i64) -> CommitTarget {
    CommitTarget {
        topic: "sync.oracle.load".to_string(),
        partition,
        offset,
    }
}
