use super::*;

pub(crate) fn classify_token(text: &str, start: usize, end: usize, hits: &mut Vec<SecretHit>) {
    let token = &text[start..end];
    if let Some(detector) = detector_for_token(token) {
        push_hit(hits, detector, token, token, start);
    }
}

fn detector_for_token(token: &str) -> Option<Detector> {
    aws_access_key_match(token)
        .or_else(|| prefixed_token_detector(token))
        .or_else(|| google_api_key_match(token))
        .or_else(|| openai_api_key_match(token))
        .or_else(|| looks_like_jwt(token).then(jwt_token_detector))
}

fn aws_access_key_match(token: &str) -> Option<Detector> {
    let has_known_prefix = [
        "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
    ]
    .iter()
    .any(|prefix| token.starts_with(prefix));
    let valid_body = token
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());

    (token.len() == 20 && has_known_prefix && valid_body).then(aws_access_key_detector)
}

fn prefixed_token_detector(token: &str) -> Option<Detector> {
    PREFIXED_TOKEN_RULES
        .iter()
        .find(|rule| rule.matches(token))
        .map(|rule| (rule.detector)())
}

struct PrefixedTokenRule {
    prefixes: &'static [&'static str],
    min_suffix_len: usize,
    suffix_char: fn(u8) -> bool,
    detector: fn() -> Detector,
}

impl PrefixedTokenRule {
    fn matches(&self, token: &str) -> bool {
        matches_prefixed_token(token, self.prefixes, self.min_suffix_len, self.suffix_char)
    }
}

const PREFIXED_TOKEN_RULES: &[PrefixedTokenRule] = &[
    PrefixedTokenRule {
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        min_suffix_len: 36,
        suffix_char: is_alnum,
        detector: github_pat_detector,
    },
    PrefixedTokenRule {
        prefixes: &["github_pat_"],
        min_suffix_len: 36,
        suffix_char: is_alnum_underscore_hyphen,
        detector: github_pat_detector,
    },
    PrefixedTokenRule {
        prefixes: &["glpat-"],
        min_suffix_len: 20,
        suffix_char: is_alnum_underscore_hyphen,
        detector: gitlab_pat_detector,
    },
    PrefixedTokenRule {
        prefixes: &["npm_"],
        min_suffix_len: 36,
        suffix_char: is_alnum_underscore_hyphen,
        detector: npm_access_token_detector,
    },
    PrefixedTokenRule {
        prefixes: &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        min_suffix_len: 10,
        suffix_char: is_alnum_hyphen,
        detector: slack_token_detector,
    },
    PrefixedTokenRule {
        prefixes: &["sk_live_", "pk_live_", "rk_live_"],
        min_suffix_len: 24,
        suffix_char: is_alnum,
        detector: stripe_live_key_detector,
    },
    PrefixedTokenRule {
        prefixes: &["sk_test_", "pk_test_", "rk_test_"],
        min_suffix_len: 24,
        suffix_char: is_alnum,
        detector: stripe_test_key_detector,
    },
    PrefixedTokenRule {
        prefixes: &["sk-ant-"],
        min_suffix_len: 20,
        suffix_char: is_alnum_underscore_hyphen,
        detector: anthropic_api_key_detector,
    },
];

fn google_api_key_match(token: &str) -> Option<Detector> {
    (token.len() == 39
        && token.starts_with("AIza")
        && token[4..].bytes().all(is_alnum_underscore_hyphen))
    .then(google_api_key_detector)
}

fn openai_api_key_match(token: &str) -> Option<Detector> {
    let rest = token
        .strip_prefix("sk-proj-")
        .or_else(|| token.strip_prefix("sk-"))?;
    (rest.len() >= 32
        && rest.bytes().all(is_alnum_underscore_hyphen)
        && shannon_entropy(rest) >= 3.5)
        .then(openai_api_key_detector)
}

pub(crate) fn detect_pem_private_keys(text: &str, hits: &mut Vec<SecretHit>) {
    let detector = pem_private_key_detector();
    let mut search_from = 0usize;
    while let Some(relative_index) = text[search_from..].find("-----BEGIN ") {
        let index = search_from + relative_index;
        let Some(end_relative) = text[index..].find("PRIVATE KEY-----") else {
            break;
        };
        let end = index + end_relative + "PRIVATE KEY-----".len();
        let matched = &text[index..end];
        if [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY-----",
        ]
        .contains(&matched)
        {
            push_hit(hits, detector, matched, matched, index);
        }
        search_from = end;
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AssignmentMode {
    OptionalQuote,
    RequiredQuote,
}
