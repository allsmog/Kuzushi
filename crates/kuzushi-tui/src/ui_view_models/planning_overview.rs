//! Pure view-model for the launch phase planner.
//!
//! The picker used to lean on three bare glyphs — `[x]`, `[~]`, `[ ]` — plus a
//! terse "reuses 1 cached" line, and left the operator to guess what Enter
//! would do and whether Kuzushi had found any prior work. This module turns the
//! picker's selection + on-disk artifact state into plain-language answers:
//!
//! - **What did Kuzushi already find here?** (`workspace_history`)
//! - **What will Enter actually do?** (`EnterPlan`)
//! - **What does each row's outcome mean?** (`RowOutcome`)
//!
//! All of it is pure over the picker's data so the renderer stays a thin
//! projection and the wording is unit-tested off-screen.

use crate::app::{
    row_disposition, PlanningArtifactState, PlanningTaskId, PlanningTaskRow, RowDisposition,
};
use std::collections::BTreeSet;
use std::time::SystemTime;

/// What confirming the picker will do with a single row, stated as a verb the
/// operator can read at a glance instead of decoding a checkbox glyph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowOutcome {
    /// Missing (or rebuild-marked) and checked — Enter runs it now.
    Run,
    /// Checked but its artifact is already cached — Enter reuses it as-is.
    Reuse,
    /// Unchecked — Enter leaves it alone this phase.
    Skip,
    /// A required CLI is missing — it cannot run regardless of selection.
    Blocked,
}

impl RowOutcome {
    pub fn from_disposition(disposition: RowDisposition) -> Self {
        match disposition {
            RowDisposition::WillRun => RowOutcome::Run,
            RowDisposition::Reused => RowOutcome::Reuse,
            RowDisposition::Off => RowOutcome::Skip,
            RowDisposition::Unavailable => RowOutcome::Blocked,
        }
    }

    /// The word shown in the row's outcome column and the legend.
    pub fn word(self) -> &'static str {
        match self {
            RowOutcome::Run => "RUN",
            RowOutcome::Reuse => "REUSE",
            RowOutcome::Skip => "SKIP",
            RowOutcome::Blocked => "BLOCKED",
        }
    }

    /// One-glance gloss for the legend so the word is never load-bearing alone.
    pub fn gloss(self) -> &'static str {
        match self {
            RowOutcome::Run => "runs now",
            RowOutcome::Reuse => "cached, reused as-is",
            RowOutcome::Skip => "unchecked, won't run",
            RowOutcome::Blocked => "needs a tool on PATH",
        }
    }

    /// Legend order, most-actionable first.
    pub const LEGEND: &'static [RowOutcome] = &[
        RowOutcome::Run,
        RowOutcome::Reuse,
        RowOutcome::Skip,
        RowOutcome::Blocked,
    ];
}

/// Resolve a row's outcome from the current selection + rebuild sets.
pub fn row_outcome(
    row: &PlanningTaskRow,
    selected: &BTreeSet<PlanningTaskId>,
    rebuild: &BTreeSet<PlanningTaskId>,
) -> RowOutcome {
    RowOutcome::from_disposition(row_disposition(row, selected, rebuild))
}

/// The exact outcome of pressing Enter, counted per bucket, so the summary line
/// can never disagree with the rows above it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnterPlan {
    /// Steps that execute now (missing artifacts + rebuild-marked cached ones).
    pub run: usize,
    /// Cached artifacts reused without running.
    pub reuse: usize,
    /// Unchecked rows left untouched.
    pub skip: usize,
    /// Rows that cannot run because a required CLI is absent.
    pub blocked: usize,
}

impl EnterPlan {
    /// A spelled-out sentence stating precisely what Enter does — the picker's
    /// single source of truth for "what happens when I confirm".
    pub fn summary_line(&self) -> String {
        if self.run == 0 {
            return self.nothing_runs_line();
        }
        let mut clauses = vec![format!("run {} new step{}", self.run, plural(self.run))];
        if self.reuse > 0 {
            clauses.push(format!(
                "reuse {} cached artifact{}",
                self.reuse,
                plural(self.reuse)
            ));
        }
        if self.skip > 0 {
            clauses.push(format!("skip {} unchecked", self.skip));
        }
        if self.blocked > 0 {
            clauses.push(format!("{} blocked", self.blocked));
        }
        format!("Enter: {}", clauses.join(" · "))
    }

    /// Enter runs nothing — say why, so a confirmed picker never looks broken.
    fn nothing_runs_line(&self) -> String {
        if self.reuse > 0 {
            return format!(
                "Enter runs nothing — all {} checked step{} are cached (reused as-is); press g to rebuild one",
                self.reuse,
                plural(self.reuse)
            );
        }
        "Enter runs nothing — no steps checked; it skips to the next phase".to_string()
    }
}

/// Tally what Enter will do across every row in the current phase.
pub fn enter_plan(
    rows: &[PlanningTaskRow],
    selected: &BTreeSet<PlanningTaskId>,
    rebuild: &BTreeSet<PlanningTaskId>,
) -> EnterPlan {
    let mut plan = EnterPlan::default();
    for row in rows {
        match row_outcome(row, selected, rebuild) {
            RowOutcome::Run => plan.run += 1,
            RowOutcome::Reuse => plan.reuse += 1,
            RowOutcome::Skip => plan.skip += 1,
            RowOutcome::Blocked => plan.blocked += 1,
        }
    }
    plan
}

/// Whether Kuzushi found prior work for this target, and if so, a returning-
/// operator summary. `Fresh` means a clean slate — nothing cached, no findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceHistory {
    Fresh,
    Prior(PriorState),
}

/// The "picking up where you left off" banner data. Every field is something
/// the operator can verify against the rows or the findings view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorState {
    /// Cached artifacts this phase can reuse instead of rebuilding.
    pub cached_artifacts: usize,
    /// Findings already recorded for the target (across all prior runs).
    pub findings: usize,
    /// Map artifacts exist on disk even when no cacheable rows appear in this
    /// phase — so a later phase never reads as a fresh start after 組 map ran.
    pub map_artifacts_built: bool,
    /// A durable phase attempt exists even if it was discarded or produced no
    /// reusable artifact. Its run evidence still makes this a returning target.
    pub prior_attempt: bool,
    /// Human phrase for when the newest cached artifact was written, e.g.
    /// "~2 h ago". `None` when no timestamp is available.
    pub last_activity: Option<String>,
}

impl PriorState {
    /// The banner's one-line summary of what already exists on disk.
    pub fn headline(&self) -> String {
        let mut parts = self.artifact_headline().into_iter().collect::<Vec<_>>();
        self.push_findings_headline(&mut parts);
        if parts.is_empty() && self.prior_attempt {
            parts.push("prior run evidence retained".to_string());
        }
        if let Some(age) = &self.last_activity {
            parts.push(format!("last activity {age}"));
        }
        parts.join(" · ")
    }

    fn artifact_headline(&self) -> Option<String> {
        if self.cached_artifacts > 0 {
            return Some(format!(
                "{} cached artifact{}",
                self.cached_artifacts,
                plural(self.cached_artifacts)
            ));
        }
        self.map_artifacts_built
            .then(|| "map artifacts ready".to_string())
    }

    fn push_findings_headline(&self, parts: &mut Vec<String>) {
        if self.findings > 0 {
            parts.push(format!(
                "{} finding{}",
                self.findings,
                plural(self.findings)
            ));
        }
    }
}

/// Derive the workspace history shown at the top of the picker. Pure over the
/// picker rows + findings count + the map-built signal + a pre-formatted
/// activity phrase, so the filesystem clock stays at the renderer boundary.
pub fn workspace_history(
    rows: &[PlanningTaskRow],
    findings: usize,
    map_artifacts_built: bool,
    prior_attempt: bool,
    last_activity: Option<String>,
) -> WorkspaceHistory {
    let cached_artifacts = rows.iter().filter(|row| is_cached(row)).count();
    if cached_artifacts == 0 && findings == 0 && !map_artifacts_built && !prior_attempt {
        return WorkspaceHistory::Fresh;
    }
    WorkspaceHistory::Prior(PriorState {
        cached_artifacts,
        findings,
        map_artifacts_built,
        prior_attempt,
        last_activity,
    })
}

/// Newest write time among this phase's cached artifacts, if any. The renderer
/// pairs this with `SystemTime::now()` to phrase "last activity ~N ago".
pub fn latest_cached_modified(rows: &[PlanningTaskRow]) -> Option<SystemTime> {
    rows.iter()
        .filter(|row| is_cached(row))
        .filter_map(|row| row.artifact_modified)
        .max()
}

/// Coarse "N ago" phrasing for orientation, not precision. `None` when `then`
/// is in the future (clock skew) or unreadable.
pub fn format_relative_age(now: SystemTime, then: SystemTime) -> Option<String> {
    let secs = now.duration_since(then).ok()?.as_secs();
    let phrase = if secs < 60 {
        "just now".to_string()
    } else if secs < 3_600 {
        format!("~{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("~{} h ago", secs / 3_600)
    } else {
        format!("~{} d ago", secs / 86_400)
    };
    Some(phrase)
}

fn is_cached(row: &PlanningTaskRow) -> bool {
    matches!(row.artifact_state, PlanningArtifactState::Cached)
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::PlanningArtifactState;
    use std::path::PathBuf;
    use std::time::Duration;
    use PlanningTaskId::*;

    fn row(id: PlanningTaskId, state: PlanningArtifactState) -> PlanningTaskRow {
        PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: state,
            artifact_modified: None,
            model_backed: id.is_model_backed(),
            required_cli: None,
            cli_available: true,
            blocker: None,
            cached_detail: None,
            last_attempt: None,
        }
    }

    fn blocked_row(id: PlanningTaskId) -> PlanningTaskRow {
        PlanningTaskRow {
            required_cli: Some("codeql"),
            cli_available: false,
            ..row(id, PlanningArtifactState::Missing)
        }
    }

    #[test]
    fn enter_plan_counts_each_outcome_bucket() {
        let rows = vec![
            row(GatherRepoContext, PlanningArtifactState::Missing), // run
            row(BuildXRay, PlanningArtifactState::Cached),          // reuse (checked)
            row(MapEntryPoints, PlanningArtifactState::Missing),    // skip (unchecked)
            blocked_row(BuildCodeQlDatabase),                       // blocked
        ];
        let selected: BTreeSet<PlanningTaskId> =
            [GatherRepoContext, BuildXRay].into_iter().collect();
        let plan = enter_plan(&rows, &selected, &BTreeSet::new());
        assert_eq!(plan.run, 1);
        assert_eq!(plan.reuse, 1);
        assert_eq!(plan.skip, 1);
        assert_eq!(plan.blocked, 1);
    }

    #[test]
    fn summary_line_spells_out_a_mixed_plan() {
        let plan = EnterPlan {
            run: 1,
            reuse: 1,
            skip: 5,
            blocked: 0,
        };
        assert_eq!(
            plan.summary_line(),
            "Enter: run 1 new step · reuse 1 cached artifact · skip 5 unchecked"
        );
    }

    #[test]
    fn summary_line_pluralizes_runs() {
        let plan = EnterPlan {
            run: 3,
            reuse: 0,
            skip: 0,
            blocked: 1,
        };
        assert_eq!(plan.summary_line(), "Enter: run 3 new steps · 1 blocked");
    }

    #[test]
    fn summary_line_explains_an_all_cached_selection() {
        let plan = EnterPlan {
            run: 0,
            reuse: 2,
            skip: 0,
            blocked: 0,
        };
        assert!(plan.summary_line().contains("runs nothing"));
        assert!(plan.summary_line().contains("press g to rebuild"));
    }

    #[test]
    fn summary_line_explains_an_empty_selection() {
        let plan = EnterPlan::default();
        assert!(plan.summary_line().contains("no steps checked"));
        assert!(plan.summary_line().contains("skips to the next phase"));
    }

    #[test]
    fn fresh_workspace_has_no_prior_state() {
        let rows = vec![row(GatherRepoContext, PlanningArtifactState::Missing)];
        assert_eq!(
            workspace_history(&rows, 0, false, false, None),
            WorkspaceHistory::Fresh
        );
    }

    #[test]
    fn cached_artifacts_or_findings_signal_prior_work() {
        let rows = vec![
            row(GatherRepoContext, PlanningArtifactState::Cached),
            row(BuildXRay, PlanningArtifactState::Cached),
            row(MapEntryPoints, PlanningArtifactState::Missing),
        ];
        let history = workspace_history(&rows, 5, true, false, Some("~2 h ago".to_string()));
        let WorkspaceHistory::Prior(state) = history else {
            panic!("expected prior state");
        };
        assert_eq!(state.cached_artifacts, 2);
        assert_eq!(state.findings, 5);
        // cached count already represents the map artifacts — no double-count.
        assert_eq!(
            state.headline(),
            "2 cached artifacts · 5 findings · last activity ~2 h ago"
        );
    }

    #[test]
    fn findings_alone_signal_prior_work_even_without_cached_artifacts() {
        // Later phases (hunt/confirm) list action rows with nothing cached, but
        // an imported-findings workspace still has prior state to announce.
        let rows = vec![row(TriageFindings, PlanningArtifactState::Action)];
        let history = workspace_history(&rows, 3, false, false, None);
        let WorkspaceHistory::Prior(state) = history else {
            panic!("expected prior state");
        };
        assert_eq!(state.cached_artifacts, 0);
        assert_eq!(state.headline(), "3 findings");
    }

    #[test]
    fn completed_map_keeps_a_later_phase_from_reading_as_fresh() {
        // Entering 崩 scan straight after 組 map: no findings yet, and the Scan
        // rows are actions with nothing cached — but the map is done, so the
        // banner must not claim a fresh start.
        let rows = vec![row(HuntTaint, PlanningArtifactState::Action)];
        let history = workspace_history(&rows, 0, true, false, None);
        let WorkspaceHistory::Prior(state) = history else {
            panic!("expected prior state once map artifacts exist");
        };
        assert_eq!(state.headline(), "map artifacts ready");
    }

    #[test]
    fn prior_attempt_does_not_claim_the_target_is_fresh() {
        let rows = vec![row(GatherRepoContext, PlanningArtifactState::Missing)];
        let history = workspace_history(&rows, 0, false, true, None);
        let WorkspaceHistory::Prior(state) = history else {
            panic!("expected retained run evidence to count as prior state");
        };
        assert_eq!(state.headline(), "prior run evidence retained");
    }

    #[test]
    fn prior_attempt_fallback_does_not_duplicate_real_history() {
        let state = PriorState {
            cached_artifacts: 1,
            findings: 0,
            map_artifacts_built: false,
            prior_attempt: true,
            last_activity: None,
        };

        assert_eq!(state.headline(), "1 cached artifact");
    }

    #[test]
    fn latest_cached_modified_picks_the_newest_cached_row() {
        let base = SystemTime::UNIX_EPOCH;
        let older = base + Duration::from_secs(100);
        let newer = base + Duration::from_secs(500);
        let mut a = row(GatherRepoContext, PlanningArtifactState::Cached);
        a.artifact_modified = Some(older);
        let mut b = row(BuildXRay, PlanningArtifactState::Cached);
        b.artifact_modified = Some(newer);
        // A missing row with a stray timestamp must not count.
        let mut c = row(MapEntryPoints, PlanningArtifactState::Missing);
        c.artifact_modified = Some(base + Duration::from_secs(9_000));
        assert_eq!(latest_cached_modified(&[a, b, c]), Some(newer));
    }

    #[test]
    fn relative_age_buckets_read_coarsely() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let ago = |secs| format_relative_age(now, now - Duration::from_secs(secs));
        assert_eq!(ago(10).as_deref(), Some("just now"));
        assert_eq!(ago(120).as_deref(), Some("~2 min ago"));
        assert_eq!(ago(7_200).as_deref(), Some("~2 h ago"));
        assert_eq!(ago(172_800).as_deref(), Some("~2 d ago"));
    }

    #[test]
    fn relative_age_rejects_future_timestamps() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let future = now + Duration::from_secs(500);
        assert_eq!(format_relative_age(now, future), None);
    }
}
