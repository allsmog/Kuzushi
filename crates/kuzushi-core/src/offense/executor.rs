//! The play executor: authorize, then run.
//!
//! [`run_play`] is the only way to execute a play against a target string.
//! It calls [`EngagementScope::authorize`] first, so a denied target never
//! reaches the transport — the gate is structurally the first thing that
//! happens, and the play receives an already-[`AuthorizedTarget`].

use super::engagement_scope::{EngagementScope, ScopeTarget};
use super::play::{Play, PlayOutcome};
use super::play_context::PlayContext;
use super::transport::PlayTransport;

/// Authorize `target_host` against `scope`, then run `play`. Returns the
/// denial reason (and never touches the transport) when the scope gate
/// refuses the target.
pub fn run_play(
    scope: &EngagementScope,
    target_host: &str,
    now_unix: u64,
    run_id: impl Into<String>,
    play: &dyn Play,
    transport: &dyn PlayTransport,
) -> Result<PlayOutcome, String> {
    let target = ScopeTarget::parse(target_host);
    let authorized = scope
        .authorize(target, now_unix)
        .map_err(|reason| format!("{}: refused {target_host}: {reason}", play.name()))?;
    let ctx = PlayContext::new(authorized, run_id);
    ctx.execute(play, transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offense::http_probe::HttpProbePlay;
    use crate::offense::transport::{PlayRequest, PlayResponse};
    use std::cell::Cell;

    /// Records whether it was asked to send, so tests can prove a denied
    /// target never reaches the network.
    struct SpyTransport {
        response: PlayResponse,
        sent: Cell<bool>,
    }

    impl SpyTransport {
        fn new(status: u16, body: &str) -> Self {
            Self {
                response: PlayResponse {
                    status,
                    headers: Vec::new(),
                    body: body.to_string(),
                    elapsed_ms: 5,
                },
                sent: Cell::new(false),
            }
        }
    }

    impl PlayTransport for SpyTransport {
        fn send(
            &self,
            _target: &ScopeTarget,
            _request: &PlayRequest,
        ) -> Result<PlayResponse, String> {
            self.sent.set(true);
            Ok(self.response.clone())
        }
    }

    fn authorized_scope(host: &str) -> EngagementScope {
        EngagementScope {
            authorized: true,
            authorization_ref: "HTB:lab".to_string(),
            in_scope: vec![super::super::engagement_scope::ScopeEntry::parse(host).unwrap()],
            ..Default::default()
        }
    }

    fn admin_probe() -> HttpProbePlay {
        HttpProbePlay::new("http-probe", PlayRequest::get("/admin"))
            .expect_status(200)
            .expect_signal("welcome admin")
    }

    #[test]
    fn denied_target_never_reaches_the_transport() {
        let scope = authorized_scope("10.0.0.5");
        let transport = SpyTransport::new(200, "welcome admin");
        let result = run_play(&scope, "10.9.9.9", 1, "run-1", &admin_probe(), &transport);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("refused"));
        assert!(
            !transport.sent.get(),
            "transport must not be touched for a denied target"
        );
    }

    #[test]
    fn authorized_target_runs_and_classifies_a_hit() {
        let scope = authorized_scope("10.0.0.5");
        let transport = SpyTransport::new(200, "welcome admin");
        let outcome = run_play(&scope, "10.0.0.5", 1, "run-1", &admin_probe(), &transport).unwrap();
        assert!(transport.sent.get());
        assert!(outcome.exploited);
        assert!(outcome.evidence.contains(&"status=200".to_string()));
        assert!(outcome
            .evidence
            .contains(&"signal:welcome admin".to_string()));
    }

    #[test]
    fn authorized_target_records_a_miss_when_conditions_fail() {
        let scope = authorized_scope("10.0.0.5");
        let transport = SpyTransport::new(403, "forbidden");
        let outcome = run_play(&scope, "10.0.0.5", 1, "run-1", &admin_probe(), &transport).unwrap();
        assert!(transport.sent.get());
        assert!(!outcome.exploited);
        assert!(outcome.summary.contains("403"));
    }
}
