use super::*;
use crate::findings::{FindingStore, Severity};
use crate::suppressions::{
    derive_rule_id, evaluate_suppressions, load_suppression_rules, remove_suppression_rule,
    run_suppression_sweep, upsert_suppression_rule, FindingRef, SuppressionOrigin,
    SuppressionPredicate, SuppressionReason, SuppressionRule, SuppressionState,
};
use crate::workspace::{load_program_scope, ScopeVerdict, WorkspaceTarget};
use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::modules) fn run_suppress_add(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("suppress:add requires an active workspace target")?;
    let store = ctx
        .findings_store
        .context("suppress:add requires a findings store")?;
    let rule = build_rule_from_input(input, workspace, store)?;
    let rule_id = rule.id.clone();
    upsert_suppression_rule(workspace, rule)?;
    let sweep = run_suppression_sweep(store, workspace, "suppress:add")?;
    let output = format!(
        "suppress:add stored {rule_id}; {} finding(s) newly suppressed",
        sweep.summary.added
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "ruleId": rule_id, "reconcile": sweep.summary, "malformedComments": sweep.report.malformed_ignore_comments }),
    ))
}

pub(in crate::modules) fn run_suppress_list(
    _input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("suppress:list requires an active workspace target")?;
    let store = ctx
        .findings_store
        .context("suppress:list requires a findings store")?;
    let sweep = run_suppression_sweep(store, workspace, "suppress:list")?;
    let rules = load_suppression_rules(workspace)?;
    let output = format!(
        "suppress:list {} rule(s); {} active, {} expired-rule(s)",
        rules.len(),
        sweep.report.active_count,
        sweep.report.expired_rules.len()
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "rules": rules.iter().map(rule_summary).collect::<Vec<_>>(),
            "activeCount": sweep.report.active_count,
            "expiredRules": sweep.report.expired_rules,
            "reopenedByExpiry": sweep.report.reopened_by_expiry,
            "malformedComments": sweep.report.malformed_ignore_comments,
            "reconcile": sweep.summary,
        }),
    ))
}

pub(in crate::modules) fn run_suppress_remove(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("suppress:remove requires an active workspace target")?;
    let store = ctx
        .findings_store
        .context("suppress:remove requires a findings store")?;
    let rule_id = string_input_any(input, &["id", "ruleId", "rule_id"])
        .context("suppress:remove requires id=<rule-id>")?;
    let reopened = reopen_findings_for_removed_rule(store, workspace, &rule_id)?;
    let removed = remove_suppression_rule(workspace, &rule_id)?;
    let output = if removed {
        format!("suppress:remove deleted {rule_id}; reopened {reopened} finding(s)")
    } else {
        format!("suppress:remove found no rule {rule_id}")
    };
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({ "ruleId": rule_id, "removed": removed, "reopened": reopened }),
    ))
}

/// Before removing a rule, emit `SuppressionRemoved` only for findings whose
/// *active* suppressor is exactly this rule. This never reopens manual
/// dismissals or findings held by another rule.
fn reopen_findings_for_removed_rule(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    rule_id: &str,
) -> Result<usize> {
    let findings = store.list_findings(usize::MAX)?;
    let scope = load_program_scope(workspace)?;
    let rules = load_suppression_rules(workspace)?;
    let now_unix = now_unix();
    let report = evaluate_suppressions(&findings, &rules, scope.as_ref(), now_unix);
    let mut reopened = 0;
    for entry in &report.states {
        if active_rule_id(&entry.state) == Some(rule_id) {
            store.append_finding_suppression_event(
                &entry.fingerprint,
                removed_event(rule_id),
            )?;
            reopened += 1;
        }
    }
    Ok(reopened)
}

fn active_rule_id(state: &SuppressionState) -> Option<&str> {
    match state {
        SuppressionState::Active(matched) => Some(matched.rule_id.as_str()),
        _ => None,
    }
}

fn removed_event(rule_id: &str) -> crate::findings::SuppressionLifecycleEvent {
    crate::findings::SuppressionLifecycleEvent {
        event_kind: crate::event_log::EventKind::SuppressionRemoved,
        reason: None,
        rule_id: Some(rule_id.to_string()),
        statement: None,
        origin: None,
        expires_at_unix: None,
        actor: "suppress:remove".to_string(),
    }
}

fn build_rule_from_input(
    input: &Value,
    _workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> Result<SuppressionRule> {
    let predicate = build_predicate(input, store)?;
    if predicate.is_empty() {
        anyhow::bail!(
            "suppress:add requires at least one matcher (finding, rule, path, tool, module, severityBelow, scopeStatus)"
        );
    }
    let reason = parse_reason(input)?;
    let statement = required_statement(input)?;
    let actor = string_input_any(input, &["actor", "author"]).unwrap_or_else(|| "operator".to_string());
    let created_at_unix = now_unix();
    let expires_at_unix = parse_days(input)?.map(|days| created_at_unix + days * 86_400);
    let id = string_input_any(input, &["ruleId", "rule_id"])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| derive_rule_id(&predicate, reason));
    Ok(SuppressionRule {
        id,
        predicate,
        reason,
        statement,
        actor,
        created_at_unix,
        expires_at_unix,
        origin: SuppressionOrigin::File,
    })
}

fn build_predicate(input: &Value, store: &FindingStore) -> Result<SuppressionPredicate> {
    Ok(SuppressionPredicate {
        finding_id: resolve_finding_ref(input, store)?,
        rule_id: string_input_any(input, &["rule", "rule_id"]),
        tool: string_input_any(input, &["tool"]),
        path_glob: compile_path(string_input_any(input, &["path"]).as_deref())?,
        module: string_input_any(input, &["module"]),
        severity_below: parse_severity_below(input)?,
        scope_status: parse_scope_status(input)?,
    })
}

/// Resolve a finding reference to a fingerprint so the stored predicate is
/// alias-independent. Errors on ambiguous or unknown references (never guesses).
fn resolve_finding_ref(input: &Value, store: &FindingStore) -> Result<Option<FindingRef>> {
    let Some(reference) = string_input_any(input, &["finding", "finding_id"]) else {
        return Ok(None);
    };
    let finding = store
        .get_finding_by_reference(&reference)?
        .with_context(|| format!("no finding matches reference {reference:?}"))?;
    Ok(Some(FindingRef(finding.fingerprint)))
}

fn compile_path(path: Option<&str>) -> Result<Option<globset::GlobMatcher>> {
    match path {
        Some(pattern) => Ok(Some(
            globset::Glob::new(pattern)
                .with_context(|| format!("invalid path glob {pattern:?}"))?
                .compile_matcher(),
        )),
        None => Ok(None),
    }
}

fn parse_reason(input: &Value) -> Result<SuppressionReason> {
    let raw = string_input_any(input, &["reason"]).context("suppress:add requires reason=<reason>")?;
    SuppressionReason::parse(&raw).with_context(|| format!("unknown suppression reason {raw:?}"))
}

fn required_statement(input: &Value) -> Result<String> {
    let statement = string_input_any(input, &["statement"])
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .context("suppress:add requires a non-empty statement=<why>")?;
    Ok(statement)
}

fn parse_severity_below(input: &Value) -> Result<Option<Severity>> {
    match string_input_any(input, &["severityBelow", "severity_below"]) {
        Some(raw) => Severity::try_from(raw.as_str())
            .map(Some)
            .with_context(|| format!("invalid severityBelow {raw:?}")),
        None => Ok(None),
    }
}

fn parse_scope_status(input: &Value) -> Result<Option<ScopeVerdict>> {
    match string_input_any(input, &["scopeStatus", "scope_status"])
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        None => Ok(None),
        Some("in-scope") | Some("in_scope") => Ok(Some(ScopeVerdict::InScope)),
        Some("out-of-scope") | Some("out_of_scope") => Ok(Some(ScopeVerdict::OutOfScope)),
        Some("unknown") => Ok(Some(ScopeVerdict::Unknown)),
        Some(other) => anyhow::bail!("invalid scopeStatus {other:?}"),
    }
}

fn parse_days(input: &Value) -> Result<Option<u64>> {
    for key in ["days", "expires_days"] {
        let Some(value) = input.get(key) else {
            continue;
        };
        if let Some(number) = value.as_u64() {
            return Ok(Some(number));
        }
        if let Some(raw) = value.as_str().map(str::trim).filter(|v| !v.is_empty()) {
            return raw
                .parse::<u64>()
                .map(Some)
                .with_context(|| format!("{key} must be a positive number of days"));
        }
    }
    Ok(None)
}

fn rule_summary(rule: &SuppressionRule) -> Value {
    json!({
        "id": rule.id,
        "reason": rule.reason.as_str(),
        "statement": rule.statement,
        "actor": rule.actor,
        "origin": rule.origin.as_str(),
        "expiresAtUnix": rule.expires_at_unix,
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
