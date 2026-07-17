use super::writer_coalescing::CoalescedItems;
use super::writer_commit::validate_stream_budget;
use super::*;
use crate::run_lifecycle::{
    RunItemId, RunItemSource, RunItemV1, SafeText, MAX_RUN_ITEM_STREAM_BYTES,
    RUN_ITEM_CRITICAL_RESERVE_BYTES,
};
use std::time::{Duration, Instant};

#[path = "writer_characterization/concurrent.rs"]
mod concurrent;
use concurrent::exercise_concurrent_producer_case;

#[path = "writer_characterization/records.rs"]
mod records;
use records::*;

#[path = "writer_characterization/saturation.rs"]
mod saturation;
use saturation::{assert_saturated_outcome, exercise_saturated_post_execution};

#[test]
fn concurrent_producer_matrix_preserves_mixed_traffic_and_reopens_at_durable_tail() {
    for producer_count in [1_usize, 8, 32] {
        exercise_concurrent_producer_case(producer_count);
    }
}

#[test]
fn coalescing_saturation_is_disclosed_instead_of_silently_dropped() {
    let mut coalesced = CoalescedItems::default();
    let overflow = 7_u64;
    for index in 0..(WRITER_CAPACITY as u64 + overflow) {
        coalesced.insert(progress(RunItemId::new(), index)).unwrap();
    }

    let pending = coalesced.drain();
    let omitted = pending
        .iter()
        .filter_map(|item| match item.record.item {
            RunItemV1::ProgressTruncated { omitted_count, .. } => Some(omitted_count),
            _ => None,
        })
        .sum::<u64>();
    assert_eq!(omitted, overflow);
    assert!(pending.iter().any(|item| matches!(
        &item.record.item,
        RunItemV1::DiagnosticNotice { message, .. }
            if message.as_str() == crate::run_lifecycle::RUN_PROGRESS_SATURATION_MARKER
    )));
    assert_eq!(pending.len(), WRITER_CAPACITY + 2);
}

#[test]
fn critical_reserve_accepts_terminal_settlement_after_normal_budget_is_exhausted() {
    let current = MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES;
    let normal = envelope(diagnostic("normal"));
    let terminal = envelope(terminal_record());

    assert!(validate_stream_budget(current, &[normal]).is_err());
    validate_stream_budget(current, &[terminal.clone()]).unwrap();
    assert!(validate_stream_budget(MAX_RUN_ITEM_STREAM_BYTES, &[terminal]).is_err());
}

#[test]
fn critical_reserve_accepts_exact_call_settlement_without_forging_an_artifact() {
    let current = MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES;
    let call_finish = envelope(tool_call_finished_record());
    let artifact = envelope(RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Dispatch,
        RunItemV1::ArtifactProduced {
            artifact: crate::run_lifecycle::ArtifactReference {
                path: SafeText::operator_visible("result.json"),
                kind: SafeText::operator_visible("result"),
                label: SafeText::operator_visible("result"),
                digest: SafeText::operator_visible("sha256:unverified"),
                byte_count: 2,
                line_count: None,
                producing_item_id: RunItemId::new(),
            },
        },
    ));

    validate_stream_budget(current, &[call_finish]).unwrap();
    assert!(validate_stream_budget(current, &[artifact]).is_err());
}

#[test]
fn saturated_post_execution_run_settles_partial_and_forbids_automatic_retry() {
    let outcome = exercise_saturated_post_execution();
    assert_saturated_outcome(&outcome);
}

#[test]
fn synchronous_flush_p95_stays_below_the_characterization_ceiling() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("flush-p95");
    let writer = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let mut latencies = Vec::new();
    for index in 0..32 {
        let started = Instant::now();
        writer
            .emit_and_flush(diagnostic(&format!("latency-{index}")))
            .unwrap();
        latencies.push(started.elapsed());
    }
    writer.shutdown().unwrap();
    latencies.sort_unstable();
    let median = latencies[latencies.len() / 2];
    let p95 = latencies[(latencies.len() * 95).div_ceil(100) - 1];

    assert!(
        p95 <= Duration::from_millis(250),
        "local persistence p95 exceeded characterization ceiling: p95={p95:?}, median={median:?}"
    );
}

/// Manual, platform-pinned regression comparison. Record the Slice-0 median
/// on the same host, then run with:
/// `KUZUSHI_SLICE0_WRITER_MEDIAN_US=<value> cargo test persistence_median_remains_within_two_times_slice_zero -- --ignored --nocapture`.
#[test]
#[ignore = "requires a same-platform Slice-0 median"]
fn persistence_median_remains_within_two_times_slice_zero() {
    let baseline_micros = std::env::var("KUZUSHI_SLICE0_WRITER_MEDIAN_US")
        .expect("set the same-platform Slice-0 writer median")
        .parse::<u64>()
        .expect("Slice-0 writer median must be integer microseconds");
    let current = measure_uncontended_writer_median(64);
    let ceiling = Duration::from_micros(baseline_micros.saturating_mul(2));
    eprintln!(
        "writer median comparison: baseline={}us current={}us ceiling={}us",
        baseline_micros,
        current.as_micros(),
        ceiling.as_micros()
    );
    assert!(current <= ceiling, "writer median regressed by more than 2x");
}

fn measure_uncontended_writer_median(sample_count: usize) -> Duration {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("flush-median-comparison");
    let writer = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let mut samples = (0..sample_count)
        .map(|index| {
            let started = Instant::now();
            writer
                .emit_and_flush(diagnostic(&format!("comparison-{index}")))
                .unwrap();
            started.elapsed()
        })
        .collect::<Vec<_>>();
    writer.shutdown().unwrap();
    samples.sort_unstable();
    samples[samples.len() / 2]
}
