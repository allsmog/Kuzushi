//! The play contract and its outcome.
//!
//! A [`Play`] is one executable step against an authorized target: it sends
//! requests through the [`PlayTransport`], observes the responses, and reports
//! a [`PlayOutcome`]. Outcomes are the links of an attack chain — an
//! `exploited` outcome's evidence becomes a precondition the next play can
//! build on. Plays receive a [`PlayContext`] (authorized target only), never a
//! raw host.

use super::play_context::PlayContext;
use super::transport::PlayTransport;

/// What a play observed and concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayOutcome {
    /// The play that produced this (e.g. `http-probe`).
    pub play: String,
    /// The target it ran against, as a string for the audit trail.
    pub target: String,
    /// True when the play's success condition was met — i.e. the step
    /// landed and can anchor the next link in the chain.
    pub exploited: bool,
    /// Human-readable one-liner.
    pub summary: String,
    /// Signals that fired (matched needles, status classifications, …).
    pub evidence: Vec<String>,
}

impl PlayOutcome {
    pub fn new(play: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            play: play.into(),
            target: target.into(),
            exploited: false,
            summary: String::new(),
            evidence: Vec::new(),
        }
    }

    pub fn exploited(mut self, summary: impl Into<String>, evidence: Vec<String>) -> Self {
        self.exploited = true;
        self.summary = summary.into();
        self.evidence = evidence;
        self
    }

    pub fn miss(mut self, summary: impl Into<String>) -> Self {
        self.exploited = false;
        self.summary = summary.into();
        self
    }
}

/// One executable step against an authorized target.
pub trait Play {
    fn name(&self) -> &str;

    fn execute(
        &self,
        ctx: &PlayContext,
        transport: &dyn PlayTransport,
    ) -> Result<PlayOutcome, String>;
}
