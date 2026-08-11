//! Review-yield session state: the operator's mode, the loaded model, the
//! open review sessions, and the memoized queue scores.
//!
//! The mode comes from the operator's `[review_yield]` config section
//! (`kuzushi_core::ReviewYieldMode`), which is global-only — a scanned
//! repository cannot arm this. `Shadow` records what a prospective ranking
//! *would* have been; `Visible` additionally lets the finding detail explain
//! the signal; neither moves a row. `WithinBand` and `Learn` reorder, and only
//! inside a complete, fully scored proof-and-severity band — they differ in
//! the key they rank that band by, never in what a row may cross.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use kuzushi_core::review_yield::application::ShadowQueueScore;
use kuzushi_core::review_yield::domain::ValidatedReviewYieldModel;
use kuzushi_core::ReviewYieldMode;

mod rank;

pub(crate) use rank::{ranks_any_band, shadow_ranked_order, RankObjective, ShadowRankRow};

/// Per-target review-yield state.
///
/// `Default` is the off state, which is also the state after a load failure:
/// there is no partial mode.
#[derive(Debug, Default)]
pub(crate) struct ReviewYieldState {
    mode: ReviewYieldMode,
    model: Option<Arc<ValidatedReviewYieldModel>>,
    /// stable fingerprint -> the session id minted when it was opened.
    open_sessions: HashMap<String, String>,
    scores: Option<ReviewYieldScoreCache>,
}

#[derive(Debug)]
struct ReviewYieldScoreCache {
    findings_revision: u64,
    cutoff_seq: u64,
    by_stable_fp: HashMap<String, ShadowQueueScore>,
}

impl ReviewYieldState {
    /// Arms the session. Mode and model are set together: a mode without a
    /// checked artifact would have nothing to score with.
    pub(crate) fn arm(&mut self, mode: ReviewYieldMode, model: ValidatedReviewYieldModel) {
        self.mode = mode;
        self.model = Some(Arc::new(model));
        self.scores = None;
    }

    /// Returns to the off state, dropping the model and every score with it.
    ///
    /// Disarming clears the model, not just the mode: a retained model would
    /// leave live scoring state behind a mode that says the signal is off.
    pub(crate) fn disarm(&mut self) {
        self.mode = ReviewYieldMode::Off;
        self.model = None;
        self.scores = None;
    }

    /// Whether the finding detail may explain the signal. False with no model
    /// loaded, whatever the configured mode says.
    pub(crate) fn shows_signal(&self) -> bool {
        self.mode.shows_signal() && self.model.is_some()
    }

    /// What this session orders a band by, and `None` when it orders nothing.
    /// A mode with no loaded model has no objective: a mode alone never moves
    /// a row.
    pub(crate) fn rank_objective(&self) -> Option<RankObjective> {
        self.model.as_ref()?;
        RankObjective::from_mode(self.mode)
    }

    pub(crate) fn model(&self) -> Option<Arc<ValidatedReviewYieldModel>> {
        self.model.clone()
    }

    /// The session already open on this finding, if the operator has not
    /// decided on it since.
    pub(crate) fn open_session(&self, stable_fp: &str) -> Option<&str> {
        self.open_sessions.get(stable_fp).map(String::as_str)
    }

    /// Mints a session id for a first open. Returns `None` when a session is
    /// already open on this finding, which is what makes a re-open silent.
    pub(crate) fn begin_session(&mut self, stable_fp: &str) -> Option<String> {
        if self.open_sessions.contains_key(stable_fp) {
            return None;
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        self.open_sessions
            .insert(stable_fp.to_string(), session_id.clone());
        Some(session_id)
    }

    /// A recorded verdict closes the session, so the next open of the same
    /// finding is a new one.
    pub(crate) fn close_session(&mut self, stable_fp: &str) {
        self.open_sessions.remove(stable_fp);
    }

    /// Target switches drop every session and score: neither means anything
    /// against a different repository.
    pub(crate) fn reset_for_target(&mut self) {
        self.open_sessions.clear();
        self.scores = None;
    }

    pub(crate) fn cached_scores(
        &self,
        findings_revision: u64,
        cutoff_seq: u64,
    ) -> Option<&HashMap<String, ShadowQueueScore>> {
        let cache = self.scores.as_ref()?;
        let current =
            cache.findings_revision == findings_revision && cache.cutoff_seq == cutoff_seq;
        current.then_some(&cache.by_stable_fp)
    }

    pub(crate) fn store_scores(
        &mut self,
        findings_revision: u64,
        cutoff_seq: u64,
        by_stable_fp: HashMap<String, ShadowQueueScore>,
    ) {
        self.scores = Some(ReviewYieldScoreCache {
            findings_revision,
            cutoff_seq,
            by_stable_fp,
        });
    }
}

/// The advisory rate ordering: higher first, fingerprint as the tie-break so
/// two identical rates rank deterministically.
pub(crate) fn compare_by_advisory_rate(left: &ShadowRankRow, right: &ShadowRankRow) -> Ordering {
    right
        .rate
        .partial_cmp(&left.rate)
        .unwrap_or(Ordering::Equal)
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

/// The knowledge-gap ordering: widest gap first.
///
/// Entropy leads, because a leaf whose prior outcomes were mixed is the one
/// the model is least sure about. Support breaks the tie the other way — of
/// two equally mixed leaves, the one resting on fewer examples learns more
/// from a verdict. Both rows are above the artifact's evidence floor already;
/// a row below it carries no key and freezes its band instead. The fingerprint
/// closes the ordering so a full tie is stable frame to frame.
pub(crate) fn compare_by_knowledge_gap(left: &ShadowRankRow, right: &ShadowRankRow) -> Ordering {
    let (Some(left_gap), Some(right_gap)) = (left.knowledge_gap, right.knowledge_gap) else {
        return Ordering::Equal;
    };
    right_gap
        .entropy_bits
        .total_cmp(&left_gap.entropy_bits)
        .then_with(|| left_gap.support.cmp(&right_gap.support))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}
