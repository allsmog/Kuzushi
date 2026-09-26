use super::*;
use url::Url;

/// How many redirects one `recon:http-fingerprint` run will follow. curl's own
/// `-L` allowed fifty and said nothing about them; a bounded walk that reports
/// the hop it stopped at is the honest form of the same convenience.
pub(crate) const MAX_REDIRECT_HOPS: usize = 10;

/// The URL a hop's response redirects to. Read only from a 3xx status carrying
/// a `location` header, and only when that location names an HTTP endpoint: a
/// relative location resolves against the hop that sent it, exactly as the HTTP
/// client would.
pub(crate) fn redirect_target(current: &Url, fingerprint: &HttpFingerprint) -> Option<Url> {
    let status = fingerprint.status?;
    if !(300..400).contains(&status) {
        return None;
    }
    let location = fingerprint.headers.get("location")?.trim();
    let next = current.join(location).ok()?;
    matches!(next.scheme(), "http" | "https").then_some(next)
}

/// Why a run stopped at a redirect instead of following it.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RedirectRefusal {
    /// `.kuzushi/scope.toml` refuses the host the redirect names. The request
    /// is never sent, because a redirect is not operator consent to probe an
    /// asset the program put out of scope.
    OutOfScope,
    /// The walk reached [`MAX_REDIRECT_HOPS`].
    HopLimit,
}

impl RedirectRefusal {
    pub(crate) fn phrase(self) -> String {
        match self {
            Self::OutOfScope => "out of scope per .kuzushi/scope.toml".to_string(),
            Self::HopLimit => format!("{MAX_REDIRECT_HOPS} redirect limit reached"),
        }
    }
}

/// A redirect the run declined, named so the operator can see the endpoint it
/// did not reach.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RedirectNotFollowed {
    pub(crate) url: String,
    pub(crate) reason: RedirectRefusal,
}

/// What a `recon:http-fingerprint` run fetched on its way to the response it
/// describes. Absent from a report whose requested URL answered without
/// redirecting anywhere.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FingerprintRedirects {
    /// Every URL fetched, in order. The first is the requested target as an
    /// absolute URL; the last is the endpoint the fingerprint describes.
    pub(crate) fetched: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_followed: Option<RedirectNotFollowed>,
}

impl FingerprintRedirects {
    /// The requested URL, named only when a later hop answered instead of it.
    pub(crate) fn followed_from(&self) -> Option<&str> {
        match self.fetched.len() > 1 {
            true => self.fetched.first().map(String::as_str),
            false => None,
        }
    }

    /// How many redirects the run followed.
    pub(crate) fn hops(&self) -> usize {
        self.fetched.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod http_redirect_tests {
    use super::*;

    fn response(status: u16, location: Option<&str>) -> HttpFingerprint {
        let mut headers = BTreeMap::new();
        if let Some(location) = location {
            headers.insert("location".to_string(), location.to_string());
        }
        HttpFingerprint {
            status: Some(status),
            headers,
            server: None,
            title: None,
            technologies: Vec::new(),
        }
    }

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn redirect_target_resolves_relative_and_absolute_locations() {
        assert_eq!(
            redirect_target(&url("http://example.com/a/b"), &response(302, Some("/login"))),
            Some(url("http://example.com/login"))
        );
        assert_eq!(
            redirect_target(
                &url("http://example.com"),
                &response(301, Some("https://cdn.example.net/x"))
            ),
            Some(url("https://cdn.example.net/x"))
        );
    }

    #[test]
    fn only_a_3xx_with_an_http_location_redirects() {
        assert_eq!(
            redirect_target(&url("http://example.com"), &response(200, Some("/login"))),
            None
        );
        assert_eq!(
            redirect_target(&url("http://example.com"), &response(302, None)),
            None
        );
        assert_eq!(
            redirect_target(
                &url("http://example.com"),
                &response(302, Some("mailto:ops@example.com"))
            ),
            None
        );
    }

    #[test]
    fn redirects_name_the_requested_url_only_once_a_later_hop_answered() {
        let direct = FingerprintRedirects {
            fetched: vec!["http://example.com/".to_string()],
            not_followed: Some(RedirectNotFollowed {
                url: "http://admin.example.com/".to_string(),
                reason: RedirectRefusal::OutOfScope,
            }),
        };
        assert_eq!(direct.followed_from(), None);
        assert_eq!(direct.hops(), 0);

        let followed = FingerprintRedirects {
            fetched: vec![
                "http://example.com/".to_string(),
                "https://example.com/".to_string(),
            ],
            not_followed: None,
        };
        assert_eq!(followed.followed_from(), Some("http://example.com/"));
        assert_eq!(followed.hops(), 1);
    }
}
