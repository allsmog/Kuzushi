//! Attack chains: ordered plays where each link builds on the last.
//!
//! A chain is the product the operator actually wants — not "here are three
//! findings" but "auth-bypass → IDOR → RCE, executed and verified, here's the
//! evidence at each hop". [`run_chain`] authorizes the target once, then runs
//! the plays in order, threading every landed step's evidence forward as
//! preconditions the next play can use. A chain is only as strong as its
//! weakest link, so it stops at the first step that does not land — you
//! cannot pivot past a hop that failed.

use super::engagement_scope::{EngagementScope, ScopeTarget};
use super::play::{Play, PlayOutcome};
use super::play_context::PlayContext;
use super::transport::PlayTransport;

/// An ordered set of plays to run against one target.
pub struct AttackChain {
    name: String,
    plays: Vec<Box<dyn Play>>,
}

impl AttackChain {
    pub fn new(name: impl Into<String>, plays: Vec<Box<dyn Play>>) -> Self {
        Self {
            name: name.into(),
            plays,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn len(&self) -> usize {
        self.plays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plays.is_empty()
    }
}

/// The recorded result of running a chain: every hop's outcome, and whether
/// the full chain completed (every link landed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOutcome {
    pub chain: String,
    pub target: String,
    pub steps: Vec<PlayOutcome>,
    pub completed: bool,
    pub summary: String,
}

/// Authorize `target_host` once, then run the chain's plays in order. A
/// denied target never reaches the transport. Evidence from each landed step
/// is threaded into the next step's context; the chain stops at the first
/// step that does not land.
pub fn run_chain(
    scope: &EngagementScope,
    target_host: &str,
    now_unix: u64,
    run_id: impl Into<String>,
    chain: &AttackChain,
    transport: &dyn PlayTransport,
) -> Result<ChainOutcome, String> {
    let authorized = scope
        .authorize(ScopeTarget::parse(target_host), now_unix)
        .map_err(|reason| format!("{}: refused {target_host}: {reason}", chain.name()))?;
    let run_id = run_id.into();

    let mut steps = Vec::with_capacity(chain.plays.len());
    let mut evidence = Vec::new();
    for play in &chain.plays {
        let ctx = PlayContext::new(authorized.clone(), run_id.clone())
            .with_preconditions(evidence.clone());
        let outcome = play.execute(&ctx, transport)?;
        let landed = outcome.exploited;
        evidence.extend(outcome.evidence.clone());
        steps.push(outcome);
        if !landed {
            break;
        }
    }

    Ok(finish_chain(chain, &authorized_target_string(&authorized), steps))
}

fn authorized_target_string(authorized: &super::play_context::AuthorizedTarget) -> String {
    authorized.target().to_string()
}

fn finish_chain(chain: &AttackChain, target: &str, steps: Vec<PlayOutcome>) -> ChainOutcome {
    let completed = steps.len() == chain.plays.len() && steps.iter().all(|step| step.exploited);
    let landed = steps.iter().filter(|step| step.exploited).count();
    let summary = if completed {
        format!("chain complete: {landed}/{} links landed", chain.plays.len())
    } else {
        format!(
            "chain broke at link {}: {}/{} landed",
            steps.len(),
            landed,
            chain.plays.len()
        )
    };
    ChainOutcome {
        chain: chain.name().to_string(),
        target: target.to_string(),
        steps,
        completed,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::engagement_scope::ScopeEntry;
    use super::super::play_context::PlayContext;
    use super::super::transport::{PlayRequest, PlayResponse};

    struct NullTransport;
    impl PlayTransport for NullTransport {
        fn send(&self, _t: &ScopeTarget, _r: &PlayRequest) -> Result<PlayResponse, String> {
            Ok(PlayResponse {
                status: 200,
                headers: Vec::new(),
                body: String::new(),
                elapsed_ms: 1,
            })
        }
    }

    /// A scripted play: lands or misses on command, emits a named token, and
    /// asserts it received the tokens earlier links emitted.
    struct ScriptedPlay {
        name: String,
        lands: bool,
        emits: String,
        expects_precondition: Option<String>,
    }

    impl Play for ScriptedPlay {
        fn name(&self) -> &str {
            &self.name
        }
        fn execute(
            &self,
            ctx: &PlayContext,
            _transport: &dyn PlayTransport,
        ) -> Result<PlayOutcome, String> {
            if let Some(expected) = &self.expects_precondition {
                assert!(
                    ctx.preconditions().iter().any(|p| p == expected),
                    "play {} expected precondition {expected:?}, got {:?}",
                    self.name,
                    ctx.preconditions()
                );
            }
            let outcome = PlayOutcome::new(self.name(), ctx.target().to_string());
            if self.lands {
                Ok(outcome.exploited(format!("{} landed", self.name), vec![self.emits.clone()]))
            } else {
                Ok(outcome.miss(format!("{} missed", self.name)))
            }
        }
    }

    fn play(name: &str, lands: bool, emits: &str, expects: Option<&str>) -> Box<dyn Play> {
        Box::new(ScriptedPlay {
            name: name.to_string(),
            lands,
            emits: emits.to_string(),
            expects_precondition: expects.map(str::to_string),
        })
    }

    fn scope(host: &str) -> EngagementScope {
        EngagementScope {
            authorized: true,
            authorization_ref: "HTB:lab".to_string(),
            in_scope: vec![ScopeEntry::parse(host).unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn full_chain_threads_evidence_and_completes() {
        let chain = AttackChain::new(
            "bypass-idor-rce",
            vec![
                play("auth-bypass", true, "token=abc", None),
                play("idor", true, "uid=1", Some("token=abc")),
                play("rce", true, "id=root", Some("uid=1")),
            ],
        );
        let outcome =
            run_chain(&scope("10.0.0.5"), "10.0.0.5", 1, "run-1", &chain, &NullTransport).unwrap();
        assert!(outcome.completed);
        assert_eq!(outcome.steps.len(), 3);
        assert!(outcome.summary.contains("3/3"));
    }

    #[test]
    fn chain_stops_at_the_first_failed_link() {
        let chain = AttackChain::new(
            "bypass-idor-rce",
            vec![
                play("auth-bypass", true, "token=abc", None),
                play("idor", false, "", Some("token=abc")),
                play("rce", true, "id=root", None),
            ],
        );
        let outcome =
            run_chain(&scope("10.0.0.5"), "10.0.0.5", 1, "run-1", &chain, &NullTransport).unwrap();
        assert!(!outcome.completed);
        // Third play never ran — the chain broke at link 2.
        assert_eq!(outcome.steps.len(), 2);
        assert!(outcome.summary.contains("broke at link 2"));
    }

    #[test]
    fn denied_target_runs_no_links() {
        let chain = AttackChain::new("probe", vec![play("auth-bypass", true, "t", None)]);
        let result = run_chain(&scope("10.0.0.5"), "10.9.9.9", 1, "run-1", &chain, &NullTransport);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("refused"));
    }
}
