use crate::identity::hash_parts;
use crate::suppressions::domain::{
    parse_utc_date_to_unix, FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason,
    SuppressionRule,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const SUPPRESSIONS_FILE_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuppressionsFile {
    version: u8,
    #[serde(default, rename = "rule")]
    rules: Vec<RawSuppressionRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSuppressionRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    reason: String,
    statement: String,
    actor: String,
    created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
    #[serde(rename = "match")]
    predicate: RawPredicate,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPredicate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    severity_below: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_status: Option<String>,
}

/// Absent file → `Ok(vec![])`. Parse or validation error → `Err` with file
/// context (no silent default), matching `load_program_scope`.
pub fn load_suppression_rules(workspace: &WorkspaceTarget) -> Result<Vec<SuppressionRule>> {
    let path = workspace.suppressions_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let file: SuppressionsFile =
        toml::from_str(&body).with_context(|| format!("Could not parse {}", path.display()))?;
    file.rules
        .into_iter()
        .map(|raw| raw.into_rule(SuppressionOrigin::File))
        .collect()
}

pub fn save_suppression_rules(
    workspace: &WorkspaceTarget,
    rules: &[SuppressionRule],
) -> Result<()> {
    workspace.ensure_state_dir()?;
    let file = SuppressionsFile {
        version: SUPPRESSIONS_FILE_VERSION,
        rules: rules.iter().map(RawSuppressionRule::from_rule).collect(),
    };
    let body = toml::to_string_pretty(&file).context("Could not serialize suppression rules")?;
    let path = workspace.suppressions_path();
    std::fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

pub fn upsert_suppression_rule(
    workspace: &WorkspaceTarget,
    rule: SuppressionRule,
) -> Result<()> {
    let mut rules = load_suppression_rules(workspace)?;
    rules.retain(|existing| existing.id != rule.id);
    rules.push(rule);
    save_suppression_rules(workspace, &rules)
}

/// Remove a rule by id. Returns whether a rule was actually removed.
pub fn remove_suppression_rule(workspace: &WorkspaceTarget, rule_id: &str) -> Result<bool> {
    let mut rules = load_suppression_rules(workspace)?;
    let before = rules.len();
    rules.retain(|existing| existing.id != rule_id);
    let removed = rules.len() != before;
    if removed {
        save_suppression_rules(workspace, &rules)?;
    }
    Ok(removed)
}

/// Deterministic id derived from the canonical predicate + reason. Used when
/// the operator does not supply an explicit id.
pub fn derive_rule_id(predicate: &SuppressionPredicate, reason: SuppressionReason) -> String {
    let canonical = canonical_predicate(predicate);
    let hash = hash_parts("suppression-rule", &[canonical.as_bytes(), reason.as_str().as_bytes()]);
    format!("sup-{}", &hash.as_str()[..8])
}

fn canonical_predicate(predicate: &SuppressionPredicate) -> String {
    let mut parts = Vec::new();
    if let Some(reference) = &predicate.finding_id {
        parts.push(format!("finding={}", reference.0));
    }
    if let Some(value) = &predicate.rule_id {
        parts.push(format!("rule={value}"));
    }
    if let Some(value) = &predicate.tool {
        parts.push(format!("tool={value}"));
    }
    if let Some(value) = &predicate.module {
        parts.push(format!("module={value}"));
    }
    if let Some(glob) = &predicate.path_glob {
        parts.push(format!("path={}", glob.glob().glob()));
    }
    if let Some(severity) = predicate.severity_below {
        parts.push(format!("severity_below={}", severity.as_str()));
    }
    if let Some(scope) = predicate.scope_status {
        parts.push(format!("scope_status={}", scope_verdict_token(scope)));
    }
    parts.join("|")
}

impl RawSuppressionRule {
    fn into_rule(self, origin: SuppressionOrigin) -> Result<SuppressionRule> {
        let reason = SuppressionReason::parse(&self.reason)
            .with_context(|| format!("unknown suppression reason {:?}", self.reason))?;
        if self.statement.trim().is_empty() {
            bail!("suppression rule statement cannot be empty");
        }
        let predicate = self.predicate.into_predicate()?;
        if predicate.is_empty() {
            bail!("suppression rule [rule.match] must set at least one key");
        }
        let expires_at_unix = resolve_expiry(self.expires_at_unix, self.expires.as_deref())?;
        let id = self
            .id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| derive_rule_id(&predicate, reason));
        Ok(SuppressionRule {
            id,
            predicate,
            reason,
            statement: self.statement,
            actor: self.actor,
            created_at_unix: self.created_at_unix,
            expires_at_unix,
            origin,
        })
    }

    fn from_rule(rule: &SuppressionRule) -> Self {
        Self {
            id: Some(rule.id.clone()),
            reason: rule.reason.as_str().to_string(),
            statement: rule.statement.clone(),
            actor: rule.actor.clone(),
            created_at_unix: rule.created_at_unix,
            expires_at_unix: rule.expires_at_unix,
            expires: None,
            predicate: RawPredicate::from_predicate(&rule.predicate),
        }
    }
}

fn resolve_expiry(explicit: Option<u64>, alias: Option<&str>) -> Result<Option<u64>> {
    match (explicit, alias) {
        (Some(_), Some(_)) => {
            bail!("suppression rule sets both expires_at_unix and expires; use exactly one")
        }
        (Some(value), None) => Ok(Some(value)),
        (None, Some(date)) => Ok(Some(parse_utc_date_to_unix(date)?)),
        (None, None) => Ok(None),
    }
}

impl RawPredicate {
    fn into_predicate(self) -> Result<SuppressionPredicate> {
        Ok(SuppressionPredicate {
            finding_id: self.finding_id.map(FindingRef),
            rule_id: self.rule_id,
            tool: self.tool,
            path_glob: compile_path(self.path.as_deref())?,
            module: self.module,
            severity_below: parse_severity(self.severity_below.as_deref())?,
            scope_status: parse_scope_status(self.scope_status.as_deref())?,
        })
    }

    fn from_predicate(predicate: &SuppressionPredicate) -> Self {
        Self {
            finding_id: predicate.finding_id.as_ref().map(|reference| reference.0.clone()),
            rule_id: predicate.rule_id.clone(),
            tool: predicate.tool.clone(),
            path: predicate.path_glob.as_ref().map(|glob| glob.glob().glob().to_string()),
            module: predicate.module.clone(),
            severity_below: predicate.severity_below.map(|s| s.as_str().to_string()),
            scope_status: predicate.scope_status.map(scope_verdict_token).map(str::to_string),
        }
    }
}

fn compile_path(path: Option<&str>) -> Result<Option<globset::GlobMatcher>> {
    match path {
        Some(pattern) => {
            let glob = globset::Glob::new(pattern)
                .with_context(|| format!("invalid path glob {pattern:?} in suppressions.toml"))?;
            Ok(Some(glob.compile_matcher()))
        }
        None => Ok(None),
    }
}

fn parse_severity(value: Option<&str>) -> Result<Option<crate::findings::Severity>> {
    match value {
        Some(raw) => crate::findings::Severity::try_from(raw)
            .map(Some)
            .with_context(|| format!("invalid severity_below {raw:?}")),
        None => Ok(None),
    }
}

fn parse_scope_status(value: Option<&str>) -> Result<Option<crate::workspace::ScopeVerdict>> {
    use crate::workspace::ScopeVerdict;
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None => Ok(None),
        Some("in-scope") | Some("in_scope") => Ok(Some(ScopeVerdict::InScope)),
        Some("out-of-scope") | Some("out_of_scope") => Ok(Some(ScopeVerdict::OutOfScope)),
        Some("unknown") => Ok(Some(ScopeVerdict::Unknown)),
        Some(other) => bail!("invalid scope_status {other:?}"),
    }
}

fn scope_verdict_token(verdict: crate::workspace::ScopeVerdict) -> &'static str {
    use crate::workspace::ScopeVerdict;
    match verdict {
        ScopeVerdict::InScope => "in-scope",
        ScopeVerdict::OutOfScope => "out-of-scope",
        ScopeVerdict::Unknown => "unknown",
    }
}
