use super::*;

pub(crate) fn list_tob_skills(input: Value) -> Result<Value> {
    let declared = declared_tob_skills();
    let spec = PluginAdapterSpec {
        tool_name: "tob:skills",
        tool_slug: "tob-audit",
        package_name: "@kuzushi/tob-skills",
        env_var: "KUZUSHI_TOB_SKILLS_DIR",
        install_hint: "pnpm add @kuzushi/tob-skills",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(missing_tob_skills_response(error.to_string(), declared));
        }
    };
    let mut resolvable = Vec::new();
    for name in declared {
        let path = root.join(name);
        if path.exists() {
            resolvable.push(json!({"id": name, "path": path.display().to_string()}));
        }
    }
    let unresolved = unresolved_tob_skills(declared, &resolvable);
    Ok(tob_skills_response(root, declared, resolvable, unresolved))
}

fn declared_tob_skills() -> [&'static str; 6] {
    [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ]
}

fn unresolved_tob_skills<'a>(declared: [&'a str; 6], resolvable: &[Value]) -> Vec<&'a str> {
    declared
        .iter()
        .filter(|name| {
            !resolvable
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(*name))
        })
        .copied()
        .collect()
}

fn missing_tob_skills_response(message: String, declared: [&str; 6]) -> Value {
    crate::module_result::failed_output_result(
        message.clone(),
        message,
        json!({
            "declared": declared,
            "resolvable": [],
            "unresolved": declared,
        }),
    )
}

fn tob_skills_response(
    root: std::path::PathBuf,
    declared: [&str; 6],
    resolvable: Vec<Value>,
    unresolved: Vec<&str>,
) -> Value {
    let output = format!(
        "Resolvable ToB skill plugins: {}\nDeclared but not resolvable: {}",
        resolvable.len(),
        unresolved.join(", ")
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "pluginRoot": root.display().to_string(),
            "declared": declared,
            "resolvable": resolvable,
            "unresolved": unresolved,
        }),
    )
}

pub(crate) fn validate_requested_tob_skills(input: &Value) -> Result<()> {
    let Some(skills) = string_array_or_csv_input(input, &["skills"]) else {
        return Ok(());
    };
    let declared = declared_tob_skills();
    let unknown = skills
        .iter()
        .filter(|skill| !declared.contains(&skill.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        anyhow::bail!(
            "tob:audit unknown skill(s): {}. Valid names: {}.",
            unknown.join(", "),
            declared.join(", ")
        );
    }
    Ok(())
}
