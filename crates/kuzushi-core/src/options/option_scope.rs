use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionScope {
    Global,
    Workspace,
    Session,
}

pub(super) fn option_scope_storage_key(scope: OptionScope) -> &'static str {
    OPTION_SCOPE_LABELS
        .iter()
        .find_map(|(candidate, label)| (*candidate == scope).then_some(*label))
        .unwrap_or("session")
}

pub(super) fn parse_option_scope(raw: &str) -> Result<OptionScope> {
    OPTION_SCOPE_LABELS
        .iter()
        .find_map(|(scope, label)| (*label == raw).then_some(*scope))
        .with_context(|| format!("unknown option scope {raw:?}"))
}

const OPTION_SCOPE_LABELS: &[(OptionScope, &str)] = &[
    (OptionScope::Global, "global"),
    (OptionScope::Workspace, "workspace"),
    (OptionScope::Session, "session"),
];
