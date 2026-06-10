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
            }),
            ScopeDecision::Denied(reason) => Err(reason),
        }
    }
}

/// Everything a play needs: the authorized target plus the run id it reports
/// evidence under.
#[derive(Debug, Clone)]
pub struct PlayContext {
    authorized: AuthorizedTarget,
    run_id: String,
}

impl PlayContext {
    pub fn new(authorized: AuthorizedTarget, run_id: impl Into<String>) -> Self {
        Self {
            authorized,
            run_id: run_id.into(),
        }
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
}
