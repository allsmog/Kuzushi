use super::*;
use crate::capabilities::recon::domain::{
    redirect_target, FingerprintRedirects, HttpFingerprint, RedirectNotFollowed, RedirectRefusal,
    MAX_REDIRECT_HOPS,
};
use crate::workspace::{ProgramScope, ScopeVerdict, TargetSyntax};
use url::Url;

/// One `recon:http-fingerprint` walk: the URL that was asked for, the redirects
/// that were followed, the response that finally answered, and the redirect the
/// walk declined to follow.
pub(crate) struct FingerprintWalk {
    requested: Url,
    followed: Vec<Url>,
    pub(crate) fingerprint: HttpFingerprint,
    not_followed: Option<RedirectNotFollowed>,
}

impl FingerprintWalk {
    /// The endpoint whose response [`Self::fingerprint`] describes.
    pub(crate) fn answered(&self) -> &Url {
        self.followed.last().unwrap_or(&self.requested)
    }

    /// What to record about the redirects, for a walk that met one. A walk whose
    /// requested URL answered outright has nothing to disclose.
    pub(crate) fn redirects(&self) -> Option<FingerprintRedirects> {
        if self.followed.is_empty() && self.not_followed.is_none() {
            return None;
        }
        let fetched = std::iter::once(&self.requested)
            .chain(self.followed.iter())
            .map(Url::to_string)
            .collect();
        Some(FingerprintRedirects {
            fetched,
            not_followed: self.not_followed.clone(),
        })
    }
}

/// Fingerprint the requested URL, following redirects one hop at a time so each
/// next host is weighed against the program scope before a request reaches it.
/// The response that answers is the one the walk describes, so the recon store
/// records the endpoint that actually served it.
pub(crate) fn walk_http_fingerprint(
    fingerprinter: &ReconHttpFingerprinter,
    requested: Url,
    scope: Option<&ProgramScope>,
    cancel: &ScanCancellation,
) -> Result<FingerprintWalk> {
    let mut followed: Vec<Url> = Vec::new();
    loop {
        let current = followed.last().unwrap_or(&requested).clone();
        let fingerprint = fingerprinter.fetch(current.as_str(), cancel)?;
        let Some(next) = redirect_target(&current, &fingerprint) else {
            return Ok(FingerprintWalk {
                requested,
                followed,
                fingerprint,
                not_followed: None,
            });
        };
        let Some(reason) = declined_redirect(&next, followed.len(), scope) else {
            followed.push(next);
            continue;
        };
        return Ok(FingerprintWalk {
            requested,
            followed,
            fingerprint,
            not_followed: Some(RedirectNotFollowed {
                url: next.to_string(),
                reason,
            }),
        });
    }
}

/// Why the walk must not fetch this redirect. A host the scope file refuses is
/// refused with the same rule the dispatch gate applies to the requested
/// target: an allow list makes an unmatched host out of scope, a deny-only file
/// leaves it unknown.
fn declined_redirect(
    next: &Url,
    followed: usize,
    scope: Option<&ProgramScope>,
) -> Option<RedirectRefusal> {
    if followed >= MAX_REDIRECT_HOPS {
        return Some(RedirectRefusal::HopLimit);
    }
    let refused = scope?.verdict_for(next.as_str(), TargetSyntax::Host) == ScopeVerdict::OutOfScope;
    refused.then_some(RedirectRefusal::OutOfScope)
}

#[cfg(test)]
mod http_fingerprint_walk_tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn scope(toml_text: &str) -> ProgramScope {
        ProgramScope::parse(toml_text).unwrap()
    }

    #[test]
    fn a_redirect_out_of_scope_is_declined() {
        let scope = scope("[in_scope]\nhosts = [\"www.example.com\"]\n");
        assert_eq!(
            declined_redirect(&url("https://cdn.other.test/"), 0, Some(&scope)),
            Some(RedirectRefusal::OutOfScope)
        );
        assert_eq!(
            declined_redirect(&url("https://www.example.com/next"), 0, Some(&scope)),
            None
        );
    }

    #[test]
    fn without_a_scope_file_only_the_hop_limit_declines() {
        assert_eq!(declined_redirect(&url("https://anywhere.test/"), 0, None), None);
        assert_eq!(
            declined_redirect(&url("https://anywhere.test/"), MAX_REDIRECT_HOPS, None),
            Some(RedirectRefusal::HopLimit)
        );
    }

    #[test]
    fn a_deny_only_scope_file_declines_only_what_it_denies() {
        let scope = scope("[out_of_scope]\nhosts = [\"admin.example.com\"]\n");
        assert_eq!(
            declined_redirect(&url("https://admin.example.com/"), 0, Some(&scope)),
            Some(RedirectRefusal::OutOfScope)
        );
        assert_eq!(
            declined_redirect(&url("https://shop.example.com/"), 0, Some(&scope)),
            None
        );
    }
}
