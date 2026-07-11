//! HTTP probe: the smallest real web-exploit-chain step.
//!
//! Sends one request and declares the step landed when the response matches
//! the success condition (an expected status and/or a signal string in the
//! body or headers). It is the building block the chain composes: e.g. an
//! auth-bypass probe whose `exploited` outcome unlocks an IDOR probe.

use super::play::{Play, PlayOutcome};
use super::play_context::PlayContext;
use super::transport::{PlayRequest, PlayResponse, PlayTransport};

/// A probe with an explicit success condition.
#[derive(Debug, Clone)]
pub struct HttpProbePlay {
    name: String,
    request: PlayRequest,
    /// Status that signifies success, if any.
    expect_status: Option<u16>,
    /// Strings that, if present in the response, signify success.
    success_signals: Vec<String>,
}

impl HttpProbePlay {
    pub fn new(name: impl Into<String>, request: PlayRequest) -> Self {
        Self {
            name: name.into(),
            request,
            expect_status: None,
            success_signals: Vec::new(),
        }
    }

    pub fn expect_status(mut self, status: u16) -> Self {
        self.expect_status = Some(status);
        self
    }

    pub fn expect_signal(mut self, signal: impl Into<String>) -> Self {
        self.success_signals.push(signal.into());
        self
    }

    fn classify(&self, response: &PlayResponse) -> (bool, Vec<String>) {
        let mut evidence = Vec::new();
        if self.expect_status == Some(response.status) {
            evidence.push(format!("status={}", response.status));
        }
        for signal in &self.success_signals {
            if response.contains(signal) {
                evidence.push(format!("signal:{signal}"));
            }
        }
        // Landed when a condition was set and at least one piece of evidence
        // fired. With no conditions, a probe never auto-declares success.
        let conditioned = self.expect_status.is_some() || !self.success_signals.is_empty();
        (conditioned && !evidence.is_empty(), evidence)
    }
}

impl Play for HttpProbePlay {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(
        &self,
        ctx: &PlayContext,
        transport: &dyn PlayTransport,
    ) -> Result<PlayOutcome, String> {
        let response = transport.send(ctx.target(), &self.request)?;
        let target = ctx.target().to_string();
        let (landed, evidence) = self.classify(&response);
        let outcome = PlayOutcome::new(self.name(), target).with_observation(response.observe(280));
        if landed {
            Ok(outcome.exploited(
                format!(
                    "{} {} -> {}",
                    self.request.method, self.request.path, response.status
                ),
                evidence,
            ))
        } else {
            Ok(outcome.miss(format!(
                "{} {} -> {} (no success condition met)",
                self.request.method, self.request.path, response.status
            )))
        }
    }
}
