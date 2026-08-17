//! Per-job budget guard: the cost ceiling for one running child and the
//! live spend probe that enforces it.
//!
//! The campaign-level `--budget` is checked between dispatches only; a
//! running job used to spend unbounded (measured: $32 against a $15 cap).
//! This module closes that hole. The child's canonical `items.jsonl` is
//! appended live by the run, so polling its summed terminal model-call
//! cost gives the dispatcher a bounded view of in-flight spend without a
//! side channel.

use kuzushi_core::run_artifacts::{run_artifact_path, terminal_model_call_cost_report};
use kuzushi_core::run_lifecycle::RunItemEnvelopeV1;
use same_file::Handle as FileIdentity;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const STARTUP_PENDING_POLL_LIMIT: u8 = 8;
const TRANSIENT_FAILURE_POLL_LIMIT: u8 = 3;

/// The ceiling for one job: the tightest of the dispatcher-wide
/// `--job-budget` and the plan row's `jobBudgetUsd`. Two present values
/// take the min — a guard must honor the strictest cap it was given.
pub(super) fn effective_job_budget(cli_usd: Option<f64>, plan_usd: Option<f64>) -> Option<f64> {
    match (positive(cli_usd), positive(plan_usd)) {
        (Some(cli), Some(plan)) => Some(cli.min(plan)),
        (cli, plan) => cli.or(plan),
    }
}

fn positive(value: Option<f64>) -> Option<f64> {
    value.filter(|usd| *usd > 0.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BudgetEvidenceReason {
    MissingAtStartup,
    OpenFailed,
    MetadataFailed,
    SeekFailed,
    ReadFailed,
    Truncated,
    Replaced,
    InvalidUtf8,
    MalformedRecord,
    WrongRun,
    BrokenSequence,
    BrokenHashChain,
    InvalidHash,
}

impl BudgetEvidenceReason {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::MissingAtStartup => {
                "lifecycle stream did not appear before the startup grace expired"
            }
            Self::OpenFailed => "lifecycle stream could not be opened",
            Self::MetadataFailed => "lifecycle stream metadata could not be read",
            Self::SeekFailed => "lifecycle stream could not be resumed at the verified offset",
            Self::ReadFailed => "lifecycle stream could not be read",
            Self::Truncated => "lifecycle stream was truncated",
            Self::Replaced => "lifecycle stream was replaced",
            Self::InvalidUtf8 => "a complete lifecycle record was not valid UTF-8",
            Self::MalformedRecord => "a complete lifecycle record was malformed",
            Self::WrongRun => "a lifecycle record belonged to another run",
            Self::BrokenSequence => "the lifecycle sequence was not contiguous",
            Self::BrokenHashChain => "the lifecycle hash chain was broken",
            Self::InvalidHash => "a lifecycle record failed hash verification",
        }
    }

    fn is_transient(self) -> bool {
        matches!(
            self,
            Self::OpenFailed | Self::MetadataFailed | Self::SeekFailed | Self::ReadFailed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum LiveSpendPoll {
    Available {
        spent_usd: f64,
    },
    Pending {
        spent_usd: f64,
    },
    Unavailable {
        spent_usd: f64,
        reason: BudgetEvidenceReason,
    },
}

impl LiveSpendPoll {
    pub(super) fn spent_usd(self) -> f64 {
        match self {
            Self::Available { spent_usd }
            | Self::Pending { spent_usd }
            | Self::Unavailable { spent_usd, .. } => spent_usd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum BudgetEvidenceDecision {
    Continue {
        spent_usd: f64,
    },
    Stop {
        spent_usd: f64,
        reason: BudgetEvidenceReason,
    },
}

/// Bounded tolerance around the raw poller. The stream may not exist on the
/// first immediate interval tick, and a live filesystem can suffer a short
/// transient read failure. Neither grace is unbounded; unknown evidence
/// eventually becomes a terminal stop instead of silently authorizing spend.
#[derive(Debug, Default)]
pub(super) struct BudgetEvidenceGuard {
    startup_pending: u8,
    transient_failures: u8,
}

impl BudgetEvidenceGuard {
    pub(super) fn observe(&mut self, poll: LiveSpendPoll) -> BudgetEvidenceDecision {
        match poll {
            LiveSpendPoll::Available { spent_usd } => self.available(spent_usd),
            LiveSpendPoll::Pending { spent_usd } => self.pending(spent_usd),
            LiveSpendPoll::Unavailable { spent_usd, reason } => self.unavailable(spent_usd, reason),
        }
    }

    fn available(&mut self, spent_usd: f64) -> BudgetEvidenceDecision {
        self.startup_pending = 0;
        self.transient_failures = 0;
        BudgetEvidenceDecision::Continue { spent_usd }
    }

    fn pending(&mut self, spent_usd: f64) -> BudgetEvidenceDecision {
        self.transient_failures = 0;
        streak_decision(
            &mut self.startup_pending,
            STARTUP_PENDING_POLL_LIMIT,
            spent_usd,
            BudgetEvidenceReason::MissingAtStartup,
        )
    }

    fn unavailable(
        &mut self,
        spent_usd: f64,
        reason: BudgetEvidenceReason,
    ) -> BudgetEvidenceDecision {
        if !reason.is_transient() {
            return BudgetEvidenceDecision::Stop { spent_usd, reason };
        }
        self.startup_pending = 0;
        streak_decision(
            &mut self.transient_failures,
            TRANSIENT_FAILURE_POLL_LIMIT,
            spent_usd,
            reason,
        )
    }
}

fn streak_decision(
    streak: &mut u8,
    limit: u8,
    spent_usd: f64,
    reason: BudgetEvidenceReason,
) -> BudgetEvidenceDecision {
    *streak = streak.saturating_add(1);
    if *streak >= limit {
        BudgetEvidenceDecision::Stop { spent_usd, reason }
    } else {
        BudgetEvidenceDecision::Continue { spent_usd }
    }
}

/// Incremental live-spend poller. It commits byte offset, sequence/hash-chain
/// cursor, and spend only after every newly completed line validates. A torn
/// final suffix is read again on the next poll and never partially trusted.
pub(super) struct LiveSpendPoller {
    path: PathBuf,
    expected_run_id: String,
    offset: u64,
    next_seq: u64,
    previous_hash: Option<String>,
    spent: f64,
    observed_stream: bool,
    stream_identity: Option<FileIdentity>,
}

impl LiveSpendPoller {
    pub(super) fn new(target: &Path, run_id: &str) -> Self {
        Self {
            path: run_artifact_path(target, run_id, "items.jsonl"),
            expected_run_id: run_id.to_string(),
            offset: 0,
            next_seq: 1,
            previous_hash: None,
            spent: 0.0,
            observed_stream: false,
            stream_identity: None,
        }
    }

    pub(super) fn poll(&mut self) -> LiveSpendPoll {
        let mut current = match self.open_verified_stream() {
            Ok(identity) => identity,
            Err(poll) => return poll,
        };
        let tail = read_appended_bytes(current.as_file_mut(), self.offset);
        let _ = self.stream_identity.get_or_insert(current);
        match tail {
            Ok(tail) => self.fold_tail(&tail),
            Err(reason) => LiveSpendPoll::Unavailable {
                spent_usd: self.spent,
                reason,
            },
        }
    }

    fn open_verified_stream(&mut self) -> Result<FileIdentity, LiveSpendPoll> {
        let current = FileIdentity::from_path(&self.path)
            .map_err(|error| self.open_failure(&error))?;
        self.observed_stream = true;
        if self
            .stream_identity
            .as_ref()
            .is_some_and(|expected| expected != &current)
        {
            return Err(LiveSpendPoll::Unavailable {
                spent_usd: self.spent,
                reason: BudgetEvidenceReason::Replaced,
            });
        }
        Ok(current)
    }

    fn open_failure(&self, error: &std::io::Error) -> LiveSpendPoll {
        if error.kind() == std::io::ErrorKind::NotFound && !self.observed_stream {
            return LiveSpendPoll::Pending {
                spent_usd: self.spent,
            };
        }
        LiveSpendPoll::Unavailable {
            spent_usd: self.spent,
            reason: BudgetEvidenceReason::OpenFailed,
        }
    }

    fn fold_tail(&mut self, tail: &[u8]) -> LiveSpendPoll {
        let Some(last_newline) = tail.iter().rposition(|byte| *byte == b'\n') else {
            return LiveSpendPoll::Available {
                spent_usd: self.spent,
            };
        };
        let outcome = validate_complete_prefix(&tail[..=last_newline], self);
        self.commit_valid_prefix(&outcome.folded, outcome.consumed);
        match outcome.failure {
            Some(reason) => LiveSpendPoll::Unavailable {
                spent_usd: self.spent,
                reason,
            },
            None => LiveSpendPoll::Available {
                spent_usd: self.spent,
            },
        }
    }

    fn commit_valid_prefix(&mut self, folded: &FoldedTail, consumed: usize) {
        self.offset += consumed as u64;
        self.next_seq = folded.next_seq;
        self.previous_hash.clone_from(&folded.previous_hash);
        self.spent += folded.added_spend_usd + 0.0;
    }
}

fn read_appended_bytes(
    file: &mut std::fs::File,
    offset: u64,
) -> Result<Vec<u8>, BudgetEvidenceReason> {
    let length = file
        .metadata()
        .map_err(|_| BudgetEvidenceReason::MetadataFailed)?
        .len();
    if length < offset {
        return Err(BudgetEvidenceReason::Truncated);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| BudgetEvidenceReason::SeekFailed)?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)
        .map_err(|_| BudgetEvidenceReason::ReadFailed)?;
    let final_length = file
        .metadata()
        .map_err(|_| BudgetEvidenceReason::MetadataFailed)?
        .len();
    if final_length < offset {
        return Err(BudgetEvidenceReason::Truncated);
    }
    Ok(tail)
}

struct FoldedTail {
    next_seq: u64,
    previous_hash: Option<String>,
    added_spend_usd: f64,
}

struct PrefixValidation {
    folded: FoldedTail,
    consumed: usize,
    failure: Option<BudgetEvidenceReason>,
}

fn validate_complete_prefix(complete: &[u8], poller: &LiveSpendPoller) -> PrefixValidation {
    let mut folded = FoldedTail {
        next_seq: poller.next_seq,
        previous_hash: poller.previous_hash.clone(),
        added_spend_usd: 0.0,
    };
    let mut consumed = 0;
    for record in complete.split_inclusive(|byte| *byte == b'\n') {
        let line = &record[..record.len().saturating_sub(1)];
        if let Err(reason) = fold_line(line, &poller.expected_run_id, &mut folded) {
            return PrefixValidation {
                folded,
                consumed,
                failure: Some(reason),
            };
        }
        consumed += record.len();
    }
    PrefixValidation {
        folded,
        consumed,
        failure: None,
    }
}

fn fold_line(
    line: &[u8],
    expected_run_id: &str,
    folded: &mut FoldedTail,
) -> Result<(), BudgetEvidenceReason> {
    let text = std::str::from_utf8(line).map_err(|_| BudgetEvidenceReason::InvalidUtf8)?;
    let envelope: RunItemEnvelopeV1 =
        serde_json::from_str(text).map_err(|_| BudgetEvidenceReason::MalformedRecord)?;
    validate_envelope(&envelope, expected_run_id, folded)?;
    folded.added_spend_usd += terminal_model_call_cost_report(&envelope.item)
        .map(|report| report.observed_usd())
        .unwrap_or(0.0);
    folded.next_seq += 1;
    folded.previous_hash = Some(envelope.event_hash);
    Ok(())
}

fn validate_envelope(
    envelope: &RunItemEnvelopeV1,
    expected_run_id: &str,
    folded: &FoldedTail,
) -> Result<(), BudgetEvidenceReason> {
    (envelope.run_id.as_str() == expected_run_id)
        .then_some(())
        .ok_or(BudgetEvidenceReason::WrongRun)?;
    (envelope.seq == folded.next_seq)
        .then_some(())
        .ok_or(BudgetEvidenceReason::BrokenSequence)?;
    (envelope.prev_event_hash == folded.previous_hash)
        .then_some(())
        .ok_or(BudgetEvidenceReason::BrokenHashChain)?;
    envelope
        .verify_hash()
        .map_err(|_| BudgetEvidenceReason::InvalidHash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_lifecycle::{
        DiagnosticLevel, ModelUsage, RunCallId, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource,
        RunItemStatus, RunItemV1, SafeText,
    };
    use std::io::Write;

    struct EnvelopeChain {
        run_id: RunId,
        next_seq: u64,
        previous_hash: Option<String>,
    }

    impl EnvelopeChain {
        fn new(run_id: &str) -> Self {
            Self {
                run_id: RunId::parse(run_id).unwrap(),
                next_seq: 1,
                previous_hash: None,
            }
        }

        fn terminal_line(&mut self, usd: f64) -> String {
            let cost = kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::from_usd(usd, "campaign test").unwrap(),
            );
            let item = RunItemV1::ModelCallFinished {
                provider: SafeText::operator_visible("test"),
                model: SafeText::operator_visible("test:model"),
                status: RunItemStatus::Completed,
                latency_ms: 1,
                usage: ModelUsage {
                    input_tokens: None,
                    output_tokens: None,
                },
                cost,
                error_class: None,
                failure: None,
            };
            self.line(item, true)
        }

        fn diagnostic_line(&mut self, message: &str) -> String {
            self.line(
                RunItemV1::DiagnosticNotice {
                    level: DiagnosticLevel::Info,
                    message: SafeText::operator_visible(message),
                },
                false,
            )
        }

        fn line(&mut self, item: RunItemV1, with_call: bool) -> String {
            let envelope = RunItemEnvelopeV1::new(
                self.next_seq,
                self.run_id.clone(),
                RunItemId::new(),
                RunItemSource::Runtime,
                item,
                self.previous_hash.clone(),
            )
            .unwrap();
            let envelope = if with_call {
                envelope.with_call(RunCallId::new()).unwrap()
            } else {
                envelope
            };
            self.next_seq += 1;
            self.previous_hash = Some(envelope.event_hash.clone());
            serde_json::to_string(&envelope).unwrap()
        }
    }

    fn write_lines(path: &Path, lines: &[String]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    fn available_spend(poll: LiveSpendPoll) -> f64 {
        match poll {
            LiveSpendPoll::Available { spent_usd } => spent_usd,
            other => panic!("expected available budget evidence, got {other:?}"),
        }
    }

    #[test]
    fn effective_budget_takes_the_tightest_present_cap() {
        assert_eq!(effective_job_budget(None, None), None);
        assert_eq!(effective_job_budget(Some(5.0), None), Some(5.0));
        assert_eq!(effective_job_budget(None, Some(3.0)), Some(3.0));
        assert_eq!(effective_job_budget(Some(5.0), Some(3.0)), Some(3.0));
        assert_eq!(effective_job_budget(Some(2.0), Some(3.0)), Some(2.0));
        assert_eq!(effective_job_budget(Some(0.0), None), None);
        assert_eq!(effective_job_budget(Some(-1.0), Some(3.0)), Some(3.0));
    }

    #[test]
    fn missing_stream_is_pending_before_first_observation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut poller = LiveSpendPoller::new(tmp.path(), "absent");
        assert_eq!(poller.poll(), LiveSpendPoll::Pending { spent_usd: 0.0 });
    }

    #[test]
    fn valid_stream_folds_terminal_cost_incrementally() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "live", "items.jsonl");
        let mut chain = EnvelopeChain::new("live");
        write_lines(&path, &[chain.terminal_line(0.4)]);
        let mut poller = LiveSpendPoller::new(tmp.path(), "live");
        assert!((available_spend(poller.poll()) - 0.4).abs() < 1e-12);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{}", chain.terminal_line(0.35)).unwrap();
        file.flush().unwrap();
        assert!((available_spend(poller.poll()) - 0.75).abs() < 1e-12);
        assert!((available_spend(poller.poll()) - 0.75).abs() < 1e-12);
    }

    #[test]
    fn incomplete_utf8_torn_tail_waits_for_its_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "utf8", "items.jsonl");
        let mut chain = EnvelopeChain::new("utf8");
        let first = chain.terminal_line(0.25);
        let next = chain.diagnostic_line("price €");
        let euro = next.find('€').expect("fixture contains euro");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "{first}").unwrap();
        file.write_all(&next.as_bytes()[..euro + 1]).unwrap();
        file.flush().unwrap();

        let mut poller = LiveSpendPoller::new(tmp.path(), "utf8");
        assert!((available_spend(poller.poll()) - 0.25).abs() < 1e-12);
        file.write_all(&next.as_bytes()[euro + 1..]).unwrap();
        file.write_all(b"\n").unwrap();
        file.flush().unwrap();
        assert!((available_spend(poller.poll()) - 0.25).abs() < 1e-12);
        assert_eq!(poller.next_seq, 3);
    }

    #[test]
    fn complete_malformed_record_is_unavailable_without_advancing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "bad", "items.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not-json}\n").unwrap();
        let mut poller = LiveSpendPoller::new(tmp.path(), "bad");
        assert_eq!(
            poller.poll(),
            LiveSpendPoll::Unavailable {
                spent_usd: 0.0,
                reason: BudgetEvidenceReason::MalformedRecord,
            }
        );
        assert_eq!(poller.offset, 0);
        assert_eq!(poller.next_seq, 1);
    }

    #[test]
    fn valid_prefix_is_retained_as_a_lower_bound_before_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "prefix", "items.jsonl");
        let mut chain = EnvelopeChain::new("prefix");
        let valid = chain.terminal_line(0.4);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{valid}\n{{not-json}}\n")).unwrap();
        let mut poller = LiveSpendPoller::new(tmp.path(), "prefix");
        assert_eq!(
            poller.poll(),
            LiveSpendPoll::Unavailable {
                spent_usd: 0.4,
                reason: BudgetEvidenceReason::MalformedRecord,
            }
        );
        assert_eq!(poller.offset, valid.len() as u64 + 1);
        assert_eq!(poller.next_seq, 2);
    }

    #[test]
    fn wrong_run_sequence_chain_and_hash_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let cases = [
            ("wrong-run", BudgetEvidenceReason::WrongRun),
            ("wrong-seq", BudgetEvidenceReason::BrokenSequence),
            ("wrong-chain", BudgetEvidenceReason::BrokenHashChain),
            ("wrong-hash", BudgetEvidenceReason::InvalidHash),
        ];
        for (name, expected) in cases {
            let path = run_artifact_path(tmp.path(), name, "items.jsonl");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let line = invalid_line(name);
            std::fs::write(&path, format!("{line}\n")).unwrap();
            let mut poller = LiveSpendPoller::new(tmp.path(), name);
            assert_eq!(
                poller.poll(),
                LiveSpendPoll::Unavailable {
                    spent_usd: 0.0,
                    reason: expected,
                },
                "case {name}"
            );
            assert_eq!(poller.offset, 0, "case {name}");
        }
    }

    fn invalid_line(case: &str) -> String {
        let run_id = if case == "wrong-run" { "other" } else { case };
        let mut chain = EnvelopeChain::new(run_id);
        let line = chain.terminal_line(0.1);
        let mut value: serde_json::Value = serde_json::from_str(&line).unwrap();
        match case {
            "wrong-seq" => value["seq"] = serde_json::json!(2),
            "wrong-chain" => value["prevEventHash"] = serde_json::json!("sha256:deadbeef"),
            "wrong-hash" => value["eventHash"] = serde_json::json!("sha256:deadbeef"),
            _ => {}
        }
        serde_json::to_string(&value).unwrap()
    }

    #[test]
    fn truncation_retains_the_last_observed_spend() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "truncate", "items.jsonl");
        let mut chain = EnvelopeChain::new("truncate");
        write_lines(&path, &[chain.terminal_line(0.6)]);
        let mut poller = LiveSpendPoller::new(tmp.path(), "truncate");
        assert!((available_spend(poller.poll()) - 0.6).abs() < 1e-12);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            poller.poll(),
            LiveSpendPoll::Unavailable {
                spent_usd: 0.6,
                reason: BudgetEvidenceReason::Truncated,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn same_size_replacement_is_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "replaced", "items.jsonl");
        let mut chain = EnvelopeChain::new("replaced");
        write_lines(&path, &[chain.diagnostic_line("heartbeat")]);
        let mut poller = LiveSpendPoller::new(tmp.path(), "replaced");
        assert_eq!(available_spend(poller.poll()), 0.0);

        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            std::fs::metadata(&replacement).unwrap().len(),
            std::fs::metadata(&path).unwrap().len()
        );
        std::fs::rename(replacement, path).unwrap();

        assert_eq!(
            poller.poll(),
            LiveSpendPoll::Unavailable {
                spent_usd: 0.0,
                reason: BudgetEvidenceReason::Replaced,
            }
        );
    }

    #[test]
    fn startup_and_transient_graces_stop_at_their_bounds_and_reset() {
        let pending = LiveSpendPoll::Pending { spent_usd: 0.0 };
        let mut guard = BudgetEvidenceGuard::default();
        for _ in 1..STARTUP_PENDING_POLL_LIMIT {
            assert_eq!(
                guard.observe(pending),
                BudgetEvidenceDecision::Continue { spent_usd: 0.0 }
            );
        }
        assert_eq!(
            guard.observe(pending),
            BudgetEvidenceDecision::Stop {
                spent_usd: 0.0,
                reason: BudgetEvidenceReason::MissingAtStartup,
            }
        );

        let transient = LiveSpendPoll::Unavailable {
            spent_usd: 0.4,
            reason: BudgetEvidenceReason::ReadFailed,
        };
        let mut guard = BudgetEvidenceGuard::default();
        for _ in 1..TRANSIENT_FAILURE_POLL_LIMIT {
            assert_eq!(
                guard.observe(transient),
                BudgetEvidenceDecision::Continue { spent_usd: 0.4 }
            );
        }
        assert_eq!(
            guard.observe(LiveSpendPoll::Available { spent_usd: 0.5 }),
            BudgetEvidenceDecision::Continue { spent_usd: 0.5 }
        );
        assert_eq!(
            guard.observe(transient),
            BudgetEvidenceDecision::Continue { spent_usd: 0.4 }
        );
    }

    #[test]
    fn durable_corruption_stops_immediately() {
        let mut guard = BudgetEvidenceGuard::default();
        assert_eq!(
            guard.observe(LiveSpendPoll::Unavailable {
                spent_usd: 1.25,
                reason: BudgetEvidenceReason::InvalidHash,
            }),
            BudgetEvidenceDecision::Stop {
                spent_usd: 1.25,
                reason: BudgetEvidenceReason::InvalidHash,
            }
        );
    }

    /// A 4-hour job's lifecycle (100k lines) must not be re-folded from byte 0
    /// on every 2-second poll. The fixture is hash-linked like the real stream.
    #[test]
    fn incremental_poll_over_100k_lifecycle_reads_only_the_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let path = run_artifact_path(tmp.path(), "long", "items.jsonl");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = std::io::BufWriter::new(file);
        let mut chain = EnvelopeChain::new("long");
        for _ in 0..100_000 {
            writeln!(writer, "{}", chain.diagnostic_line("heartbeat")).unwrap();
        }
        writer.flush().unwrap();

        let mut poller = LiveSpendPoller::new(tmp.path(), "long");
        assert_eq!(available_spend(poller.poll()), 0.0);
        let started = std::time::Instant::now();
        for _ in 0..50 {
            assert_eq!(available_spend(poller.poll()), 0.0);
        }
        let per_poll = started.elapsed() / 50;
        assert!(
            per_poll < std::time::Duration::from_millis(5),
            "steady-state poll cost {per_poll:?} — tail polling regressed to a full re-fold"
        );
    }
}
