use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    summary: String,
    changes: Vec<Change>,
    unsupported: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Change {
    RunTool {
        tool: String,
        input: serde_json::Map<String, Value>,
    },
    SetOption {
        tool: String,
        global: bool,
        name: String,
        value: Value,
    },
    Note {
        text: String,
    },
}

pub(super) fn validate(registry: &ModuleRegistry, input: &Value, value: &Value) -> Result<()> {
    let proposal: Proposal = serde_json::from_value(value.clone())
        .context("workflow proposal shape is invalid; no repair request was made")?;
    bounded_text(&proposal.summary)?;
    anyhow::ensure!(
        proposal.changes.len() <= 6 && proposal.unsupported.len() <= 6,
        "workflow proposal exceeds six changes or questions"
    );
    for note in &proposal.unsupported {
        bounded_text(note)?;
    }
    for change in proposal.changes {
        validate_change(registry, input, change)?;
    }
    Ok(())
}

fn validate_change(registry: &ModuleRegistry, input: &Value, change: Change) -> Result<()> {
    match change {
        Change::RunTool {
            tool,
            input: proposed,
        } => validate_run(registry, input, &tool, &proposed),
        Change::SetOption {
            tool,
            global,
            name,
            value,
        } => {
            let _operator_scope = global;
            let descriptor = selected_tool(registry, input, &tool)?;
            allowed_option(descriptor, &name)?;
            bounded_value(&value)
        }
        Change::Note { text } => bounded_text(&text),
    }
}

fn validate_run(
    registry: &ModuleRegistry,
    input: &Value,
    tool: &str,
    proposed: &serde_json::Map<String, Value>,
) -> Result<()> {
    anyhow::ensure!(
        input["phase"].is_string(),
        "run_tool needs a selected investigation phase"
    );
    let descriptor = selected_tool(registry, input, tool)?;
    for (name, value) in proposed {
        allowed_option(descriptor, name)?;
        bounded_value(value)?;
    }
    Ok(())
}

fn selected_tool<'a>(
    registry: &'a ModuleRegistry,
    input: &Value,
    name: &str,
) -> Result<&'a ToolDescriptor> {
    let tool = registry
        .resolve_tool(name)
        .context("proposal names an unknown tool")?;
    anyhow::ensure!(
        registry.tool_is_discoverable(name) && available(tool, input),
        "proposal tool is outside the supplied supported phase and effect boundary"
    );
    Ok(tool)
}

fn allowed_option(tool: &ToolDescriptor, name: &str) -> Result<()> {
    let option = tool
        .options
        .iter()
        .find(|option| option.matches_name_or_alias(name))
        .context("proposal names an undeclared tool option")?;
    anyhow::ensure!(
        !protected_option(&option.name),
        "proposal cannot alter model, target, spending or internal work bindings"
    );
    Ok(())
}

fn protected_option(name: &str) -> bool {
    matches!(
        name,
        "model"
            | "target"
            | "allowanceRef"
            | "budgetUsd"
            | "autoPatch"
            | "autoVerify"
            | "verificationMode"
    ) || name.starts_with("__")
        || name.starts_with("MODEL_")
}

fn bounded_text(text: &str) -> Result<()> {
    anyhow::ensure!(
        !text.trim().is_empty() && text.len() <= 4096,
        "proposal text must contain one to 4096 bytes"
    );
    Ok(())
}

fn bounded_value(value: &Value) -> Result<()> {
    anyhow::ensure!(
        serde_json::to_vec(value)?.len() <= 4096,
        "proposed option exceeds 4096 bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_core_metadata_fits_one_bounded_tool_free_request() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let request = super::super::request(
            &registry,
            &json!({"goal":"Owned repository workflow", "maxOutputTokens":4096}),
            std::path::Path::new("/owned-fixture"),
            "openai:test",
        )
        .unwrap();
        assert!(request.prompt.len() <= 128 * 1024);
        assert!(request.tool_policy.tools.is_empty());
        assert!(!request.tool_policy.mcps);
        assert_eq!(request.runtime_options.unwrap().max_model_turns, Some(1));
    }

    fn proposal(changes: Value) -> Value {
        json!({"summary":"Owned defensive workflow draft","changes":changes,"unsupported":[]})
    }

    #[test]
    fn declarations_and_phase_bound_the_proposed_work() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let change = json!({"kind":"run_tool","tool":"semgrep:scan","input":{}});
        assert!(validate(
            &registry,
            &json!({"phase":"scan"}),
            &proposal(json!([change.clone()]))
        )
        .is_ok());
        assert!(validate(&registry, &json!({}), &proposal(json!([change.clone()]))).is_err());
        assert!(validate(
            &registry,
            &json!({"phase":"map"}),
            &proposal(json!([change]))
        )
        .is_err());
    }

    #[test]
    fn protected_unknown_excessive_and_out_of_scope_changes_are_refused() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        for name in ["model", "target", "allowanceRef", "unknown-option"] {
            let change = json!({"kind":"run_tool","tool":"semgrep:scan","input":{(name):true}});
            assert!(validate(
                &registry,
                &json!({"phase":"scan"}),
                &proposal(json!([change]))
            )
            .is_err());
        }
        for tool in ["patch:finding", "fuzz:prove", "codeql:scan", "missing:tool"] {
            let change = json!({"kind":"run_tool","tool":tool,"input":{}});
            assert!(validate(
                &registry,
                &json!({"phase":"scan"}),
                &proposal(json!([change]))
            )
            .is_err());
        }
        let seven = (0..7)
            .map(|_| json!({"kind":"note","text":"Owned note"}))
            .collect::<Vec<_>>();
        assert!(validate(&registry, &json!({}), &proposal(json!(seven))).is_err());
    }

    #[test]
    fn malformed_shapes_are_not_silently_filtered_or_repaired() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        for value in [
            json!({}),
            json!({"summary":"","changes":[],"unsupported":[]}),
            proposal(json!([{"kind":"unexpected","text":"note"}])),
        ] {
            assert!(validate(&registry, &json!({}), &value).is_err());
        }
    }
}
