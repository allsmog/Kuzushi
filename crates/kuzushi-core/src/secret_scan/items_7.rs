use super::prelude::*;
use super::*;

pub(crate) fn classify_token(text: &str, start: usize, end: usize, hits: &mut Vec<SecretHit>) {
    let token = &text[start..end];
    if token.len() == 20
        && [
            "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
        ]
        .iter()
        .any(|prefix| token.starts_with(prefix))
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        push_hit(hits, aws_access_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(
        token,
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        36,
        is_alnum,
    ) {
        push_hit(hits, github_pat_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(
        token,
        &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        10,
        is_alnum_hyphen,
    ) {
        push_hit(hits, slack_token_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk_live_", "pk_live_", "rk_live_"], 24, is_alnum) {
        push_hit(hits, stripe_live_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk_test_", "pk_test_", "rk_test_"], 24, is_alnum) {
        push_hit(hits, stripe_test_key_detector(), token, token, start);
        return;
    }

    if token.len() == 39
        && token.starts_with("AIza")
        && token[4..].bytes().all(is_alnum_underscore_hyphen)
    {
        push_hit(hits, google_api_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk-ant-"], 20, is_alnum_underscore_hyphen) {
        push_hit(hits, anthropic_api_key_detector(), token, token, start);
        return;
    }

    if token.starts_with("sk-") {
        let rest = token
            .strip_prefix("sk-proj-")
            .or_else(|| token.strip_prefix("sk-"));
        if let Some(rest) = rest {
            if rest.len() >= 32
                && rest.bytes().all(is_alnum_underscore_hyphen)
                && shannon_entropy(rest) >= 3.5
            {
                push_hit(hits, openai_api_key_detector(), token, token, start);
                return;
            }
        }
    }

    if looks_like_jwt(token) {
        push_hit(hits, jwt_token_detector(), token, token, start);
    }
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
