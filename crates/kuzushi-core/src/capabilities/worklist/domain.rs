//! Pure domain types for the risk-ranked file worklist.
//!
//! The worklist is a deterministic fold over existing rankers. Every row
//! carries the raw evidence of each contributing ranker (never a laundered
//! normalized float alone), and every contributor declares an honest state so
//! "not requested" is distinguishable from "unavailable".

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A ranker that can contribute risk signal to a file. Phase A folds
/// `AttackSurface`, `ScanCoverage`, and (opt-in) `SystemsHunt`; the remaining
/// variants exist so their Phase B/C state machine needs no fold rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Contributor {
    AttackSurface,
    ScanCoverage,
    SystemsHunt,
    PrefilterHistory,
    CallGraphFanIn,
    Complexity,
}

impl Contributor {
    pub fn id(self) -> &'static str {
        match self {
            Self::AttackSurface => "attack-surface",
            Self::ScanCoverage => "scan-coverage",
            Self::SystemsHunt => "systems-hunt",
            Self::PrefilterHistory => "prefilter-history",
            Self::CallGraphFanIn => "call-graph-fan-in",
            Self::Complexity => "complexity",
        }
    }

    pub fn glyph(self) -> char {
        match self {
            Self::AttackSurface => 'A',
            Self::ScanCoverage => 'C',
            Self::SystemsHunt => 'S',
            Self::PrefilterHistory => 'P',
            Self::CallGraphFanIn => 'F',
            Self::Complexity => 'X',
        }
    }
}

/// The honesty type: a contributor is never a bare present/absent bool.
/// `Unavailable` and `Degraded` must carry a reason string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContributorState {
    Live,
    Unavailable { reason: String },
    Degraded { reason: String },
    NotRequested,
}

/// One ranker's evidence for one file. Keeps the raw value and a human display
/// alongside the normalized weight and the declared normalization method, so a
/// surface renders `92/100`, not a laundered `0.71`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Citation {
    pub contributor: Contributor,
    pub raw: f64,
    pub raw_display: String,
    pub normalized: f32,
    pub normalization: &'static str,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorklistRow {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub score: f32,
    pub rank: usize,
    pub citations: Vec<Citation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
}

/// A file present in the inputs but with no live ranking signal. Explicit,
/// never silently dropped.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnrankedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Worklist {
    pub rows: Vec<WorklistRow>,
    /// The number of files that crossed the signal threshold before the row
    /// limit truncated `rows`. Callers report the true ranked population (e.g.
    /// "run worklist for all {ranked_total}") rather than the capped `rows.len`.
    pub ranked_total: usize,
    pub contributors: BTreeMap<Contributor, ContributorState>,
    pub unranked: Vec<UnrankedFile>,
    pub degraded: Vec<String>,
}

/// Declared combination weights in one place, so the scorer stays a table
/// lookup rather than a match ladder.
pub const WEIGHTS: &[(Contributor, f32)] = &[
    (Contributor::AttackSurface, 1.0),
    (Contributor::SystemsHunt, 0.8),
    (Contributor::PrefilterHistory, 0.5),
    (Contributor::CallGraphFanIn, 0.4),
    (Contributor::ScanCoverage, 0.3),
    (Contributor::Complexity, 0.3),
];

pub(crate) fn weight_of(contributor: Contributor) -> f32 {
    WEIGHTS
        .iter()
        .find(|(candidate, _)| *candidate == contributor)
        .map(|(_, weight)| *weight)
        .unwrap_or(0.0)
}
