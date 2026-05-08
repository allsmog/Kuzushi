use super::prelude::*;
use super::*;

pub(crate) fn unquote_tune_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
}
