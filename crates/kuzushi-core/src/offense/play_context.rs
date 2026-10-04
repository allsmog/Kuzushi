//! Authorization proof and the context a play runs in.
//!
//! [`AuthorizedTarget`] is the type-level guarantee that a target cleared the
//! engagement-scope gate. Its fields are private and its only constructor is
//! [`EngagementScope::authorize`], so possessing one *is* proof that
//! [`EngagementScope::decide`] returned `Allowed`. Plays take a
//! [`PlayContext`] (which owns an `AuthorizedTarget`), never a raw host — so
//! there is no code path that sends traffic at an unscoped target.

use super::engagement_scope::{EngagementScope, ScopeDecision, ScopeTarget};

/// Proof that a target was authorized by an [`EngagementScope`] at a moment
/// in time. Carries the authorization reference and timestamp for the audit
/// trail.
#[derive(Debug, Clone)]
pub struct AuthorizedTarget {
    target: ScopeTarget,
    authorization_ref: String,
    authorized_at_unix: u64,
    scope: EngagementScope,
}

impl AuthorizedTarget {
    pub fn target(&self) -> &ScopeTarget {
        &self.target
    }

    pub fn authorization_ref(&self) -> &str {
        &self.authorization_ref
    }

    pub fn authorized_at_unix(&self) -> u64 {
        self.authorized_at_unix
    }
}

impl EngagementScope {
    /// Authorize `target` for live operations, or return the denial reason.
    /// This is the single door: a play can only obtain an
    /// [`AuthorizedTarget`] through here.
    pub fn authorize(
        &self,
        target: ScopeTarget,
        now_unix: u64,
    ) -> Result<AuthorizedTarget, String> {
        match self.decide(&target, now_unix) {
            ScopeDecision::Allowed => Ok(AuthorizedTarget {
                target,
                authorization_ref: self.authorization_ref.trim().to_string(),
                authorized_at_unix: now_unix,
                scope: self.clone(),
            }),
            ScopeDecision::Denied(reason) => Err(reason),
        }
    }
}

/// Everything a play needs: the authorized target plus the run id it reports
/// evidence under, and any evidence captured by earlier links in the chain.
#[derive(Debug, Clone)]
pub struct PlayContext {
    authorized: AuthorizedTarget,
    run_id: String,
    preconditions: Vec<String>,
}

impl PlayContext {
    /// All outbound requests, including those made by custom plays, recheck scope.
    pub fn execute(
        &self,
        play: &dyn super::play::Play,
        transport: &dyn super::transport::PlayTransport,
    ) -> Result<super::play::PlayOutcome, String> {
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|time| time.as_secs())
                .map_err(|error| error.to_string())
        };
        play.execute(
            self,
            &AuthorizedTransport {
                authorized: &self.authorized,
                inner: transport,
                now: &now,
            },
        )
    }

    pub fn new(authorized: AuthorizedTarget, run_id: impl Into<String>) -> Self {
        Self {
            authorized,
            run_id: run_id.into(),
            preconditions: Vec::new(),
        }
    }

    /// Seed the context with evidence captured by earlier chain links so a
    /// play can build on it (e.g. reuse a token an auth-bypass step landed).
    pub fn with_preconditions(mut self, preconditions: Vec<String>) -> Self {
        self.preconditions = preconditions;
        self
    }

    pub fn target(&self) -> &ScopeTarget {
        self.authorized.target()
    }

    pub fn authorization_ref(&self) -> &str {
        self.authorized.authorization_ref()
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Evidence accumulated by earlier plays in the chain.
    pub fn preconditions(&self) -> &[String] {
        &self.preconditions
    }
}

struct AuthorizedTransport<'a> {
    authorized: &'a AuthorizedTarget,
    inner: &'a dyn super::transport::PlayTransport,
    now: &'a dyn Fn() -> Result<u64, String>,
}

impl super::transport::PlayTransport for AuthorizedTransport<'_> {
    fn send(
        &self,
        target: &ScopeTarget,
        request: &super::transport::PlayRequest,
    ) -> Result<super::transport::PlayResponse, String> {
        if target != self.authorized.target() {
            return Err("request target differs from authorization".into());
        }
        match self.authorized.scope.decide(target, (self.now)()?) {
            ScopeDecision::Allowed => self.inner.send(target, request),
            ScopeDecision::Denied(reason) => Err(format!("outbound request refused: {reason}")),
        }
    }
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use crate::offense::engagement_scope::{ScopeEntry, ScopeWindow};
    use crate::offense::transport::{PlayRequest, PlayResponse, PlayTransport};
    use std::cell::Cell;

    struct CountTransport(Cell<usize>);
    impl PlayTransport for CountTransport {
        fn send(&self, _: &ScopeTarget, _: &PlayRequest) -> Result<PlayResponse, String> {
            self.0.set(self.0.get() + 1);
            Ok(PlayResponse {
                status: 200,
                headers: vec![],
                body: String::new(),
                elapsed_ms: 0,
            })
        }
    }

    #[test]
    fn a_second_request_after_expiration_never_reaches_transport() {
        let scope = EngagementScope {
            authorized: true,
            authorization_ref: "test".into(),
            in_scope: vec![ScopeEntry::parse("example.test").unwrap()],
            window: Some(ScopeWindow {
                not_after_unix: Some(10),
                ..Default::default()
            }),
            ..Default::default()
        };
        let authorized = scope
            .authorize(ScopeTarget::parse("example.test"), 9)
            .unwrap();
        let inner = CountTransport(Cell::new(0));
        let clock = Cell::new(9);
        let now = || Ok(clock.get());
        let transport = AuthorizedTransport {
            authorized: &authorized,
            inner: &inner,
            now: &now,
        };
        assert!(transport
            .send(authorized.target(), &PlayRequest::get("/"))
            .is_ok());
        clock.set(11);
        assert!(transport
            .send(authorized.target(), &PlayRequest::get("/"))
            .unwrap_err()
            .contains("window"));
        assert_eq!(inner.0.get(), 1);
    }
}
