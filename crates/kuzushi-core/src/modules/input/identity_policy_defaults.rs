use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{Map, Value};

pub(in crate::modules) fn bind_identity_policy_defaults(
    tool_name: &str,
    mut input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    if !matches!(tool_name, "sast:scan" | "triage:run") {
        return Ok(input);
    }
    let object = input
        .as_object_mut()
        .context("identity policy input must be an object")?;
    let fold = string_value(object, "identityFold");
    let reconcile = string_value(object, "identityReconcile");
    let defaults = resolve_defaults(ctx, fold, reconcile)?;
    if tool_name == "sast:scan" {
        object.insert("identityFold".to_string(), Value::String(defaults.identity_fold));
    } else {
        object.insert(
            "identityReconcile".to_string(),
            Value::String(defaults.identity_reconcile),
        );
    }
    Ok(input)
}

fn resolve_defaults(
    ctx: &ToolExecutionContext<'_>,
    fold: Option<&str>,
    reconcile: Option<&str>,
) -> Result<crate::findings::IdentityPolicyDefaults> {
    let Some(workspace) = ctx.workspace else {
        return Ok(conservative_defaults(fold, reconcile));
    };
    let paths = crate::ConfigPaths::from_target(Some(workspace.root()))?;
    crate::findings::resolve_identity_policy_defaults(
        &paths.global_state_dir(),
        workspace.root(),
        fold,
        reconcile,
    )
}

fn conservative_defaults(
    fold: Option<&str>,
    reconcile: Option<&str>,
) -> crate::findings::IdentityPolicyDefaults {
    crate::findings::IdentityPolicyDefaults {
        identity_fold: fold.unwrap_or("legacy").to_string(),
        identity_reconcile: reconcile.unwrap_or("off").to_string(),
        approval_status: crate::findings::IdentityPolicyApprovalStatus::Missing,
        identity_fold_explicit: fold.is_some(),
        identity_reconcile_explicit: reconcile.is_some(),
    }
}

fn string_value<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}
