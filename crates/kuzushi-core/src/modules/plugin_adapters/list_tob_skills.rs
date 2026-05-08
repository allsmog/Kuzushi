use super::*;

pub(in crate::modules) fn list_tob_skills(input: Value) -> Result<Value> {
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
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
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "declared": declared,
                    "resolvable": [],
                    "unresolved": declared,
                },
            }));
        }
    };
    let mut resolvable = Vec::new();
    for name in declared {
        let path = root.join(name);
        if path.exists() {
            resolvable.push(json!({"id": name, "path": path.display().to_string()}));
        }
    }
    let unresolved = declared
        .iter()
        .filter(|name| {
            !resolvable
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(*name))
        })
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": true,
        "output": format!("Resolvable ToB skill plugins: {}\nDeclared but not resolvable: {}", resolvable.len(), unresolved.join(", ")),
        "data": {
            "pluginRoot": root.display().to_string(),
            "declared": declared,
            "resolvable": resolvable,
            "unresolved": unresolved,
        },
    }))
}

pub(in crate::modules) fn validate_requested_tob_skills(input: &Value) -> Result<()> {
    let Some(skills) = string_array_or_csv_input(input, &["skills"]) else {
        return Ok(());
    };
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
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
