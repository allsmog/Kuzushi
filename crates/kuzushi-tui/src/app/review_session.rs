//! Prospective review sessions: recording that substantive review of a
//! finding began, before any verdict exists, and keeping the queue's advisory
//! scores current for the modes that display them.
//!
//! Every function here is inert unless the operator's `[review_yield]` config
//! names a model that loads. The queue the operator sees is byte-for-byte the
//! baseline in every mode but the two ordering ones; in `visible`,
//! `within-band`, and `learn` a view model may read the memoized scores,
//! through `visible_review_yield_score` to explain a finding on screen and
//! through `within_band_scores` to order rows inside a band. Neither path scores: scoring happens off the render
//! path, in `ShellEffect::ScoreReviewYieldQueue` and `RecordReviewSessionStart`.

use super::*;
use kuzushi_core::findings::ProofConfidence;
use kuzushi_core::review_yield::application::{score_review_queue_shadow, ShadowQueueScore};
use kuzushi_core::review_yield::domain::{severity_rank, FEATURE_SCHEMA_ID};
use kuzushi_core::storage_v3::writer_actor::ReviewSessionWrite;
use kuzushi_core::{ReviewYieldExportProvenance, ReviewYieldMode};
use std::collections::HashMap;

#[cfg(test)]
mod tests;

impl ShellApp {
    /// Loads the artifact named by `[review_yield]` and arms the configured
    /// mode, or reports why neither happened.
    ///
    /// Fail-closed: a rejected artifact leaves the session off and says so,
    /// rather than quietly running a lesser mode. The state always ends up
    /// describing the config, so a mode of `off` disarms rather than leaving
    /// an earlier arming in place.
    ///
    /// Arming an ordering or display mode scores the queue that already
    /// hydrated at launch, so the first frame the operator sees is the one the
    /// mode describes.
    pub(crate) fn arm_review_yield_from_config(&mut self) -> Vec<ShellEffect> {
        self.apply_review_yield_config();
        self.review_yield_queue_scoring_effects()
    }

    pub(crate) fn apply_review_yield_config(&mut self) {
        let review_yield = self.config().review_yield.clone();
        let Some(model_path) = review_yield
            .model_path
            .as_ref()
            .filter(|_| review_yield.mode != ReviewYieldMode::Off)
        else {
            self.runtime_state.review_yield_mut().disarm();
            return;
        };
        match kuzushi_core::review_yield::persistence::load_model_artifact(model_path) {
            Ok(model) => {
                self.runtime_state
                    .review_yield_mut()
                    .arm(review_yield.mode, model);
                self.log("review-yield", armed_mode_notice(review_yield.mode));
            }
            Err(error) => {
                self.runtime_state.review_yield_mut().disarm();
                self.set_error_notice(
                    "review-yield",
                    format!(
                        "model rejected: {error}. review_yield.mode = \"{}\" is not running — no other mode was substituted. Next: fix review_yield.model_path in the global config, or set review_yield.mode = \"off\".",
                        review_yield.mode.label()
                    ),
                );
            }
        }
    }

    /// Whether the finding detail may explain the advisory signal.
    pub(crate) fn shows_review_yield_signal(&self) -> bool {
        self.runtime_state.review_yield().shows_signal()
    }

    /// Scoring effects for a queue that has just become current — at launch
    /// once the mode is armed, and after every findings reload.
    ///
    /// The ordering and display modes need scores before the operator opens
    /// anything: a queue that only reordered after the first open would show
    /// two different orders for the same data and blame neither on the model.
    /// Empty when the mode neither orders nor explains, when no model loaded,
    /// and when the memoized scores already cover this queue, so re-running it
    /// on an unchanged generation costs nothing.
    pub(crate) fn review_yield_queue_scoring_effects(&self) -> Vec<ShellEffect> {
        self.review_yield_queue_score_request()
            .map(|apply| vec![ShellEffect::ScoreReviewYieldQueue(apply)])
            .unwrap_or_default()
    }

    fn review_yield_queue_score_request(&self) -> Option<ReviewYieldScoreApply> {
        if !self.scores_the_visible_queue() {
            return None;
        }
        self.runtime_state.review_yield().model()?;
        self.target_path_buf()?;
        let feature_cutoff_seq = self.findings_read_watermark()?;
        let queue = self.review_queue_rows();
        self.queue_needs_scoring(feature_cutoff_seq, &queue)
            .then(|| ReviewYieldScoreApply {
                target: self.target_owned(),
                feature_cutoff_seq,
                queue,
            })
    }

    /// Whether the armed mode does anything with a score. `shadow` records
    /// sessions and nothing else, so it has no queue to keep current.
    fn scores_the_visible_queue(&self) -> bool {
        self.shows_review_yield_signal() || self.review_yield_rank_objective().is_some()
    }

    fn queue_needs_scoring(&self, cutoff: u64, queue: &[ReviewQueueRow]) -> bool {
        !queue.is_empty() && cached_queue_scores(self, cutoff, queue).is_none()
    }

    /// The memoized queue scores, if they describe the queue on screen.
    ///
    /// A pure read: the ordering path calls this on the render path and must
    /// never trigger scoring. Absent scores leave every band in baseline
    /// order, which is the fail-closed answer.
    pub(crate) fn within_band_scores(&self) -> Option<&HashMap<String, ShadowQueueScore>> {
        self.review_yield_rank_objective()?;
        let cutoff = self.findings_read_watermark()?;
        self.runtime_state
            .review_yield()
            .cached_scores(self.findings_revision(), cutoff)
    }

    /// What the armed mode orders a band by, or `None` when nothing may move.
    pub(crate) fn review_yield_rank_objective(&self) -> Option<RankObjective> {
        self.runtime_state.review_yield().rank_objective()
    }

    /// What the review-yield signal was doing in this session, for an export
    /// to disclose. `None` when the mode is off, so an export from an
    /// unarmed session carries no block at all rather than an empty one.
    ///
    /// The model id is present only when an artifact actually loaded: a
    /// configured path that was rejected leaves the id absent rather than
    /// naming a model that never scored anything.
    pub(crate) fn review_yield_export_provenance(&self) -> Option<ReviewYieldExportProvenance> {
        let mode = self.config().review_yield.mode;
        if mode == ReviewYieldMode::Off {
            return None;
        }
        Some(ReviewYieldExportProvenance {
            mode,
            model_id: self
                .runtime_state
                .review_yield()
                .model()
                .map(|model| model.model_id().to_string()),
        })
    }

    /// The advisory score for this finding, for display only.
    ///
    /// `None` outside `Visible` mode, and `None` whenever the memoized scores
    /// were measured against a different set of findings or a different read
    /// cutoff: a number computed over another queue is not this finding's
    /// signal, and showing it anyway would be the fake number this feature
    /// exists to avoid.
    pub(crate) fn visible_review_yield_score(
        &self,
        finding: &Finding,
    ) -> Option<&ShadowQueueScore> {
        if !self.shows_review_yield_signal() {
            return None;
        }
        let cutoff = self.findings_read_watermark()?;
        self.runtime_state
            .review_yield()
            .cached_scores(self.findings_revision(), cutoff)?
            .get(finding_stable_fp(finding))
    }

    /// Effects for "the operator opened this finding to review it".
    ///
    /// Returns nothing unless a model is loaded, a target is active, the
    /// finding is in the visible queue, and the read cutoff is known. Cursor
    /// movement never reaches here.
    ///
    /// A first open both records the session and scores the queue. A re-open
    /// records nothing — it is the same session — but `Visible` mode still
    /// needs a current score for the detail it is about to draw, so it asks
    /// for one when the memoized scores no longer describe this queue.
    pub(crate) fn review_session_start_effects(&mut self, finding: &Finding) -> Vec<ShellEffect> {
        let Some(request) = self.review_session_request(finding) else {
            return Vec::new();
        };
        let stable_fp = finding_stable_fp(finding).to_string();
        match self
            .runtime_state
            .review_yield_mut()
            .begin_session(&stable_fp)
        {
            Some(review_session_id) => {
                vec![ShellEffect::RecordReviewSessionStart(ReviewSessionApply {
                    target: self.target_owned(),
                    finding: finding.clone(),
                    review_session_id,
                    feature_cutoff_seq: request.feature_cutoff_seq,
                    queue: request.queue,
                    baseline_index: request.baseline_index,
                    objective: request.objective,
                })]
            }
            None => self.rescore_visible_queue_effects(request),
        }
    }

    /// The score-only request a re-open needs when the session displays or
    /// orders by the signal. Empty when nothing is displayed, or when the
    /// memoized scores already cover the queue on screen.
    fn rescore_visible_queue_effects(&self, request: ReviewSessionRequest) -> Vec<ShellEffect> {
        if !self.shows_review_yield_signal()
            || cached_queue_scores(self, request.feature_cutoff_seq, &request.queue).is_some()
        {
            return Vec::new();
        }
        vec![ShellEffect::ScoreReviewYieldQueue(ReviewYieldScoreApply {
            target: self.target_owned(),
            feature_cutoff_seq: request.feature_cutoff_seq,
            queue: request.queue,
        })]
    }

    /// The session id to attach to a verdict on this finding, if one is open.
    pub(crate) fn open_review_session_id(&self, finding: &Finding) -> Option<String> {
        self.runtime_state
            .review_yield()
            .open_session(finding_stable_fp(finding))
            .map(str::to_string)
    }

    /// A new target invalidates every open session and cached score: neither
    /// means anything against a different repository.
    pub(crate) fn reset_review_sessions_for_target(&mut self) {
        self.runtime_state.review_yield_mut().reset_for_target();
    }

    /// A recorded verdict ends the session; the next open starts a new one.
    pub(crate) fn close_review_session(&mut self, finding: &Finding) {
        let stable_fp = finding_stable_fp(finding).to_string();
        self.runtime_state
            .review_yield_mut()
            .close_session(&stable_fp);
    }

    fn review_session_request(&self, finding: &Finding) -> Option<ReviewSessionRequest> {
        self.runtime_state.review_yield().model()?;
        self.target_path_buf()?;
        let feature_cutoff_seq = self.findings_read_watermark()?;
        let queue = self.review_queue_rows();
        let stable_fp = finding_stable_fp(finding);
        let baseline_index = queue.iter().position(|row| row.stable_fp == stable_fp)?;
        Some(ReviewSessionRequest {
            feature_cutoff_seq,
            queue,
            baseline_index,
            objective: self.recorded_rank_objective(),
        })
    }

    /// The objective a recorded rank is measured under: the mode's own
    /// ordering key when it has one, and the yield ranking otherwise. A
    /// `shadow` or `visible` session orders nothing, so the prospective
    /// question its rank answers is still the yield one — and the label
    /// travels with the number either way.
    fn recorded_rank_objective(&self) -> RankObjective {
        self.review_yield_rank_objective()
            .unwrap_or(RankObjective::Yield)
    }

    /// The review queue in *baseline* order — the order with no model in
    /// play. Read-only: this consumes the shared projection and never
    /// rewrites it.
    ///
    /// Baseline rather than displayed order, so `baseline_rank` on a session
    /// record stays the genuine counterfactual even in `within-band` mode,
    /// where the displayed order is itself the advisory ranking.
    fn review_queue_rows(&self) -> Vec<ReviewQueueRow> {
        crate::ui_view_models::baseline_sorted_finding_alias_indices(self)
            .into_iter()
            .filter_map(|(_, index)| self.findings().get(index))
            .map(review_queue_row)
            .collect()
    }

    pub(super) fn record_review_session_effect(&mut self, apply: ReviewSessionApply) {
        match self.write_review_session(&apply) {
            Ok(()) => {}
            Err(error) => {
                // The session is lost, not the interaction: an open must never
                // fail because a measurement could not be recorded.
                self.runtime_state
                    .review_yield_mut()
                    .close_session(finding_stable_fp(&apply.finding));
                self.log("review-yield", format!("session not recorded: {error}"));
            }
        }
    }

    /// Refreshes the memoized queue scores without recording anything.
    ///
    /// This is the display path: `Visible` mode asks for it when the operator
    /// re-opens a finding whose queue has moved on. A failure leaves the cache
    /// stale, so the detail says the signal is unavailable rather than showing
    /// a number measured against a different queue.
    pub(super) fn score_review_yield_queue_effect(&mut self, apply: ReviewYieldScoreApply) {
        if let Err(error) = self.refresh_review_yield_scores(&apply) {
            self.log("review-yield", format!("queue not scored: {error}"));
        }
    }

    fn refresh_review_yield_scores(&mut self, apply: &ReviewYieldScoreApply) -> anyhow::Result<()> {
        let workspace = workspace_for_target(apply.target.as_ref())?;
        let model = self.loaded_review_yield_model()?;
        self.review_yield_scores_for_queue(
            &workspace,
            &apply.queue,
            apply.feature_cutoff_seq,
            &model,
        )?;
        Ok(())
    }

    fn write_review_session(&mut self, apply: &ReviewSessionApply) -> anyhow::Result<()> {
        let workspace = workspace_for_target(apply.target.as_ref())?;
        let model = self.loaded_review_yield_model()?;
        let scores = self.review_yield_scores_for_queue(
            &workspace,
            &apply.queue,
            apply.feature_cutoff_seq,
            &model,
        )?;
        let write = review_session_write(apply, &model, &scores);
        kuzushi_core::workspace::record_review_session_started(&workspace, write)?;
        Ok(())
    }

    fn loaded_review_yield_model(
        &self,
    ) -> anyhow::Result<std::sync::Arc<kuzushi_core::review_yield::domain::ValidatedReviewYieldModel>>
    {
        self.runtime_state
            .review_yield()
            .model()
            .ok_or_else(|| anyhow::anyhow!("no review-yield model is loaded"))
    }

    /// Scores are memoized per findings generation and read cutoff, so a queue
    /// that has not changed costs no further projection reads.
    fn review_yield_scores_for_queue(
        &mut self,
        workspace: &kuzushi_core::WorkspaceTarget,
        queue: &[ReviewQueueRow],
        cutoff: u64,
        model: &kuzushi_core::review_yield::domain::ValidatedReviewYieldModel,
    ) -> anyhow::Result<HashMap<String, ShadowQueueScore>> {
        if let Some(cached) = cached_queue_scores(self, cutoff, queue) {
            return Ok(cached);
        }
        let identities: Vec<Option<String>> =
            queue.iter().map(|row| row.identity_id.clone()).collect();
        let scored = score_review_queue_shadow(workspace, &identities, cutoff, model)?;
        let by_stable_fp: HashMap<String, ShadowQueueScore> = queue
            .iter()
            .map(|row| row.stable_fp.clone())
            .zip(scored)
            .collect();
        let revision = self.findings_revision();
        self.runtime_state
            .review_yield_mut()
            .store_scores(revision, cutoff, by_stable_fp.clone());
        Ok(by_stable_fp)
    }
}

/// What the log says once a model is armed. Each mode states exactly what it
/// does to the queue, because that is the one thing the modes differ on.
fn armed_mode_notice(mode: ReviewYieldMode) -> &'static str {
    match mode {
        ReviewYieldMode::WithinBand => {
            "model loaded — review rows may reorder inside a proof and severity band; bands themselves never move"
        }
        ReviewYieldMode::Learn => {
            "model loaded — once the queue is scored, review rows may reorder inside a proof and severity band, findings the model has least evidence about first; bands themselves never move"
        }
        ReviewYieldMode::Visible => {
            "model loaded — the finding detail explains the signal, review order unchanged"
        }
        _ => "model loaded — recording only, review order unchanged",
    }
}

struct ReviewSessionRequest {
    feature_cutoff_seq: u64,
    queue: Vec<ReviewQueueRow>,
    baseline_index: usize,
    objective: RankObjective,
}

/// A cache hit only counts when every current queue row is covered; a queue
/// that gained a row is rescored rather than partially answered.
fn cached_queue_scores(
    app: &ShellApp,
    cutoff: u64,
    queue: &[ReviewQueueRow],
) -> Option<HashMap<String, ShadowQueueScore>> {
    let cached = app
        .runtime_state
        .review_yield()
        .cached_scores(app.findings_revision(), cutoff)?;
    queue
        .iter()
        .map(|row| {
            cached
                .get(&row.stable_fp)
                .map(|score| (row.stable_fp.clone(), score.clone()))
        })
        .collect()
}

fn review_queue_row(finding: &Finding) -> ReviewQueueRow {
    let proof = ProofConfidence::classify(finding);
    ReviewQueueRow {
        stable_fp: finding_stable_fp(finding).to_string(),
        fingerprint: finding.fingerprint.clone(),
        identity_id: finding.identity_id.clone(),
        proof_rank: proof.rank(),
        proof_band: proof.as_str().to_string(),
        severity_rank: severity_rank(finding.severity),
        severity: finding.severity.as_str().to_string(),
        finding_id: finding.id,
    }
}

fn review_session_write(
    apply: &ReviewSessionApply,
    model: &kuzushi_core::review_yield::domain::ValidatedReviewYieldModel,
    scores: &HashMap<String, ShadowQueueScore>,
) -> ReviewSessionWrite {
    let row = &apply.queue[apply.baseline_index];
    let score = scores.get(&row.stable_fp);
    let shadow_rank = shadow_rank(apply, scores);
    ReviewSessionWrite {
        review_session_id: apply.review_session_id.clone(),
        stable_fp: row.stable_fp.clone(),
        identity_id: row.identity_id.clone(),
        finding_id: row.finding_id,
        feature_schema_id: FEATURE_SCHEMA_ID.to_string(),
        feature_snapshot_hash: score
            .and_then(ShadowQueueScore::feature_snapshot_hash)
            .map(str::to_string),
        feature_cutoff_seq: apply.feature_cutoff_seq,
        model_id: model.model_id().to_string(),
        eligibility: eligibility_kind(score).to_string(),
        baseline_rank: rank_of(apply.baseline_index),
        shadow_rank,
        shadow_rank_objective: shadow_rank.map(|_| apply.objective),
        queue_size: u32::try_from(apply.queue.len()).unwrap_or(u32::MAX),
        proof_band: row.proof_band.clone(),
        severity: row.severity.clone(),
        actor: "operator".to_string(),
    }
}

/// A queue row with no score at all is a different fact from one the model
/// declined to score, so the absence has its own discriminant.
fn eligibility_kind(score: Option<&ShadowQueueScore>) -> &'static str {
    score.map_or("noScoreRecorded", ShadowQueueScore::eligibility_kind)
}

/// The advisory rank, recorded only when this row's own score was eligible.
/// An ineligible row would otherwise report its baseline position dressed up as
/// a prediction.
///
/// Ranked by the session's active objective, and stored beside its label: a
/// `learn` session records where the learn ordering put this row, a
/// yield-ordering one records the yield position, and the reader never has to
/// guess which question an identical number answered.
fn shadow_rank(
    apply: &ReviewSessionApply,
    scores: &HashMap<String, ShadowQueueScore>,
) -> Option<u32> {
    let row = &apply.queue[apply.baseline_index];
    scores.get(&row.stable_fp)?.eligible_rate()?;
    let rows: Vec<ShadowRankRow> = apply
        .queue
        .iter()
        .map(|row| shadow_rank_row(row, scores.get(&row.stable_fp)))
        .collect();
    let order = shadow_ranked_order(&rows, apply.objective);
    let position = order
        .iter()
        .position(|&index| index == apply.baseline_index)?;
    Some(rank_of(position))
}

fn shadow_rank_row(row: &ReviewQueueRow, score: Option<&ShadowQueueScore>) -> ShadowRankRow {
    ShadowRankRow {
        proof_rank: row.proof_rank,
        severity_rank: row.severity_rank,
        rate: score.and_then(ShadowQueueScore::eligible_rate),
        knowledge_gap: score.and_then(ShadowQueueScore::eligible_knowledge_gap),
        fingerprint: row.fingerprint.clone(),
    }
}

fn rank_of(index: usize) -> u32 {
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}
