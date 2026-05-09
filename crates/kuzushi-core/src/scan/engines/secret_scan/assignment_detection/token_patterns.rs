use super::*;

pub(crate) fn matches_prefixed_token(
    token: &str,
    prefixes: &[&str],
    min_rest: usize,
    rest_char: fn(u8) -> bool,
) -> bool {
    prefixes.iter().any(|prefix| {
        token
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() >= min_rest && rest.bytes().all(rest_char))
    })
}

pub(crate) fn looks_like_jwt(token: &str) -> bool {
    let parts = token.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts[0].len() >= 11
        && parts[1].len() >= 8
        && parts[2].len() >= 4
        && parts
            .iter()
            .all(|part| part.bytes().all(is_alnum_underscore_hyphen))
}
