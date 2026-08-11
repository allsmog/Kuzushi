//! The finding detail's review-yield section, as pre-formatted text.
//!
//! Everything a renderer needs is a `String` here. The renderer holds no
//! percentages, no rounding, no eligibility rules, and no access to the score
//! cache — it lays out labels this module already decided.
//!
//! Two claims are load-bearing and are repeated on screen in both states: this
//! is a historical reviewer-outcome signal, and it decides nothing. It never
//! reorders the queue and it never stands in for a human verdict.

use crate::app::ShellApp;
use kuzushi_core::review_yield::application::{ShadowQueueScore, UnscorableReason};
use kuzushi_core::review_yield::domain::{
    PathBranch, ReviewYieldEligibility, ReviewYieldPathStep, ReviewYieldSignal,
};
use kuzushi_core::Finding;

/// Required wording next to every rendering of the signal, in both states.
pub(crate) const REVIEW_YIELD_ADVISORY_LINE_1: &str =
    "Advisory historical reviewer-outcome signal.";
pub(crate) const REVIEW_YIELD_ADVISORY_LINE_2: &str =
    "Not vulnerability proof and not a human decision.";

/// The detail-pane review-yield section.
///
/// `None` on the detail model means the section does not render at all — the
/// operator did not turn the signal on, so there is no phantom section and no
/// hint that a number is being withheld.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ReviewYieldDetailModel {
    Signal(ReviewYieldSignalViewModel),
    /// The signal is on but this finding has none. `message` says which fact
    /// stopped it, never a blank and never a stand-in number.
    Unavailable {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReviewYieldSignalViewModel {
    /// Historical positive rate, e.g. `74%`.
    pub(crate) rate_label: String,
    /// Prior reviewed examples in this leaf, e.g. `42 (31 confirmed · 11 rejected)`.
    pub(crate) support_label: String,
    /// 95% interval, e.g. `59%–85%`.
    pub(crate) interval_label: String,
    /// Outcome entropy, e.g. `0.83 bits`.
    pub(crate) entropy_label: String,
    /// The model this came from, in a form safe to put on screen.
    pub(crate) model_label: String,
    /// The splits the finding took, in order.
    pub(crate) path_steps: Vec<String>,
    /// Why the entropy and support above are the numbers ordering the queue.
    /// Present only while Learn mode is actually ranking a band of it.
    pub(crate) learn_context: Option<&'static str>,
}

/// What Learn mode is doing to the queue, said beside the numbers it orders
/// by.
///
/// Two sentences, because two things here are easy to misread: the gap is the
/// model's rather than the finding's, and a band nobody could rank is still in
/// baseline order.
pub(crate) const REVIEW_YIELD_LEARN_CONTEXT: &str =
    "Learn ordering: this queue puts findings the model has least evidence about first — \
     fewer, more mixed prior examples rank earlier. A band holding any unscored row keeps \
     its baseline order.";

/// The section for the finding the detail pane is about to draw.
///
/// Pure read of app state: no store, no filesystem, no scoring. Scoring
/// happens off the render path in `ShellEffect::ScoreReviewYieldQueue` and
/// `RecordReviewSessionStart`.
pub(crate) fn review_yield_detail_for(
    app: &ShellApp,
    finding: &Finding,
) -> Option<ReviewYieldDetailModel> {
    if !app.shows_review_yield_signal() {
        return None;
    }
    let learn_context =
        super::findings::learn_ordering_ranks_queue(app).then_some(REVIEW_YIELD_LEARN_CONTEXT);
    let Some(score) = app.visible_review_yield_score(finding) else {
        return Some(unavailable(NOT_SCORED_YET));
    };
    Some(match score {
        ShadowQueueScore::Scored { signal, .. } => detail_for_signal(signal, learn_context),
        ShadowQueueScore::Unscorable(reason) => unavailable(&unscorable_message(*reason)),
    })
}

/// A finding the operator has not opened yet in this session. Scoring covers
/// the whole queue at once, so one open answers every row.
const NOT_SCORED_YET: &str =
    "not scored yet — open this finding from the review queue to compute its signal";

fn unavailable(message: &str) -> ReviewYieldDetailModel {
    ReviewYieldDetailModel::Unavailable {
        message: message.to_string(),
    }
}

fn detail_for_signal(
    signal: &ReviewYieldSignal,
    learn_context: Option<&'static str>,
) -> ReviewYieldDetailModel {
    match signal_view_model(signal, learn_context) {
        Some(view) => ReviewYieldDetailModel::Signal(view),
        None => unavailable(&ineligible_message(&signal.eligibility)),
    }
}

/// A view model only when the model committed to the score *and* the leaf
/// supplied every number. A partially populated leaf would put a headline
/// percentage next to a blank interval, which reads as a rendering bug rather
/// than as missing evidence.
fn signal_view_model(
    signal: &ReviewYieldSignal,
    learn_context: Option<&'static str>,
) -> Option<ReviewYieldSignalViewModel> {
    if !signal.is_eligible() {
        return None;
    }
    let (low, high) = signal.credible_interval_95?;
    Some(ReviewYieldSignalViewModel {
        rate_label: percent_label(signal.smoothed_positive_rate?),
        support_label: support_label(signal.positive_count?, signal.negative_count?),
        interval_label: format!("{}–{}", percent_label(low), percent_label(high)),
        entropy_label: format!("{:.2} bits", signal.leaf_entropy_bits?),
        model_label: display_model_label(&signal.model_id),
        path_steps: signal.decision_path.iter().map(path_step_label).collect(),
        learn_context,
    })
}

fn percent_label(rate: f64) -> String {
    format!("{:.0}%", (rate * 100.0).clamp(0.0, 100.0))
}

fn support_label(positive: u32, negative: u32) -> String {
    let total = u64::from(positive) + u64::from(negative);
    format!("{total} ({positive} confirmed · {negative} rejected)")
}

/// Why this finding has no score. Every variant says something specific: an
/// operator who reads "signal unavailable" and nothing else cannot tell a
/// broken model from a finding the model has never seen.
fn ineligible_message(eligibility: &ReviewYieldEligibility) -> String {
    match eligibility {
        // Eligible reaches here only when the leaf withheld a number, which is
        // a defect in the artifact rather than a fact about the finding.
        ReviewYieldEligibility::Eligible => {
            "the model returned an incomplete leaf — signal unavailable".to_string()
        }
        ReviewYieldEligibility::Disabled => "the signal is turned off for this session".to_string(),
        ReviewYieldEligibility::NoModelConfigured => {
            "no model is configured — nothing was scored".to_string()
        }
        ReviewYieldEligibility::InvalidModelHash => {
            "the model file failed its integrity check — signal unavailable".to_string()
        }
        ReviewYieldEligibility::UnsupportedModelSchema => {
            "the model file format is not supported — signal unavailable".to_string()
        }
        ReviewYieldEligibility::FeatureSchemaMismatch => {
            "the model expects a different set of inputs — signal unavailable".to_string()
        }
        ReviewYieldEligibility::MissingRequiredFeature { feature } => {
            format!("this finding lacks a required input ({feature}) — signal unavailable")
        }
        ReviewYieldEligibility::UnknownCategory { feature, value } => {
            format!(
                "{feature} is {value}, which the model never saw in training — signal unavailable"
            )
        }
        ReviewYieldEligibility::InsufficientLeafSupport { support } => {
            format!(
                "only {support} prior reviewed examples match this finding, below this model's evidence floor — no rate is shown"
            )
        }
        ReviewYieldEligibility::OutOfDistribution { reason } => {
            format!(
                "this finding is outside the model's known data ({reason}) — signal unavailable"
            )
        }
    }
}

/// Why a queue row never reached the model at all. Distinct from eligibility:
/// nothing was evaluated, so there is no decision path to explain.
fn unscorable_message(reason: UnscorableReason) -> String {
    match reason {
        UnscorableReason::NoDurableIdentity => {
            "this finding has no durable identity, so no review history joins to it"
        }
        UnscorableReason::NoStoredSnapshot => {
            "no stored record of this finding exists yet — rescan the target to create one"
        }
        UnscorableReason::SnapshotUnreadable => {
            "this finding's stored record could not be read — signal unavailable"
        }
    }
    .to_string()
}

/// A model id fit for an operator surface.
///
/// A full `blake3:<64 hex>` is 71 unbreakable columns of hash. Clip it the way
/// the pane already clips fingerprints, keeping the algorithm prefix so the
/// value stays comparable and never reads as a bare clipped hex run. A
/// schema-version-shaped id (`review-tree-v1`) is rewritten so the version
/// stops looking like a contract tag on screen.
fn display_model_label(model_id: &str) -> String {
    clipped_digest(model_id)
        .or_else(|| unpacked_version_suffix(model_id))
        .unwrap_or_else(|| model_id.to_string())
}

/// `blake3:<64 hex>` → `blake3:<12 hex>…`, keeping the prefix so the value is
/// still comparable and never reads as a bare clipped hex run.
fn clipped_digest(model_id: &str) -> Option<String> {
    const VISIBLE_DIGEST: usize = 12;
    let (algorithm, digest) = model_id.split_once(':')?;
    let clippable = digest.len() > VISIBLE_DIGEST && is_hex_run(digest);
    clippable.then(|| format!("{algorithm}:{}…", &digest[..VISIBLE_DIGEST]))
}

/// `review-tree-v1` → `review-tree (v1)`, so the version stops reading as a
/// contract tag on an operator surface.
fn unpacked_version_suffix(model_id: &str) -> Option<String> {
    let (name, version) = model_id.rsplit_once("-v")?;
    let versioned =
        !name.is_empty() && !version.is_empty() && version.chars().all(|c| c.is_ascii_digit());
    versioned.then(|| format!("{name} (v{version})"))
}

fn is_hex_run(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// One split the finding took, as a comparison an operator can check against
/// the finding in front of them.
fn path_step_label(step: &ReviewYieldPathStep) -> String {
    let feature = &step.feature;
    match &step.taken {
        PathBranch::Left { threshold } => format!("{feature} ≤ {}", number_label(*threshold)),
        PathBranch::Right { threshold } => format!("{feature} > {}", number_label(*threshold)),
        PathBranch::Branch { value } => format!("{feature} = {value}"),
        PathBranch::Missing { direction } => {
            format!("{feature} absent, followed the {direction} branch")
        }
    }
}

/// Thresholds are learned values like `1.5`; render them the way a person
/// reads a number, without a trailing `.0` on a whole one.
fn number_label(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        return format!("{value:.0}");
    }
    format!("{value}")
}

#[cfg(test)]
mod tests;
