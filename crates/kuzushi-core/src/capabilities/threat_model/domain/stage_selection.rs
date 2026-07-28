use super::*;

pub(crate) fn read_stages(
    input: &Value,
    tool_name: &str,
    methodology: &str,
) -> Result<Vec<String>> {
    if methodology != "pasta" {
        reject_pasta_stages_for_other_methodologies(input, tool_name, methodology)?;
        return Ok(Vec::new());
    }
    let Some(items) = read_stage_items(input, tool_name)? else {
        return Ok(default_stages());
    };
    read_valid_stages(items, tool_name)
}

fn reject_pasta_stages_for_other_methodologies(
    input: &Value,
    tool_name: &str,
    methodology: &str,
) -> Result<()> {
    if input.get("stages").is_some() {
        anyhow::bail!(
            "{tool_name} stages s1-s4 are PASTA-specific and cannot be selected for methodology={methodology}"
        );
    }
    Ok(())
}

fn read_valid_stages(items: &[Value], tool_name: &str) -> Result<Vec<String>> {
    let (stages, unknown) = collect_requested_stages(items, tool_name)?;
    reject_unknown_stages(&unknown, tool_name)?;
    Ok(stages_or_default(stages))
}

fn read_stage_items<'a>(input: &'a Value, tool_name: &str) -> Result<Option<&'a Vec<Value>>> {
    let Some(raw) = input.get("stages") else {
        return Ok(None);
    };
    let Value::Array(items) = raw else {
        anyhow::bail!("{tool_name} stages must be an array of stage ids");
    };
    Ok(Some(items))
}

fn collect_requested_stages(
    items: &[Value],
    tool_name: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut stages = Vec::new();
    let mut unknown = Vec::new();
    for item in items {
        record_requested_stage(
            read_stage_entry(item, tool_name)?,
            &mut stages,
            &mut unknown,
        );
    }
    Ok((stages, unknown))
}

fn read_stage_entry<'a>(item: &'a Value, tool_name: &str) -> Result<&'a str> {
    let Some(stage) = item
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        anyhow::bail!("{tool_name} stages entries must be strings");
    };
    Ok(stage)
}

fn record_requested_stage(stage: &str, stages: &mut Vec<String>, unknown: &mut Vec<String>) {
    if VALID_STAGES.contains(&stage) {
        stages.push(stage.to_string());
    } else {
        unknown.push(stage.to_string());
    }
}

fn reject_unknown_stages(unknown: &[String], tool_name: &str) -> Result<()> {
    if !unknown.is_empty() {
        anyhow::bail!(
            "{tool_name} unknown stage(s): {}. Valid: s1, s2, s3, s4.",
            unknown.join(", ")
        );
    }
    Ok(())
}

fn stages_or_default(stages: Vec<String>) -> Vec<String> {
    if stages.is_empty() {
        default_stages()
    } else {
        stages
    }
}

fn default_stages() -> Vec<String> {
    VALID_STAGES.iter().map(|stage| stage.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pasta_selects_pasta_stages() {
        assert_eq!(
            read_stages(&json!({}), "threat-model:build", "pasta").unwrap(),
            vec!["s1", "s2", "s3", "s4"]
        );
        assert!(read_stages(&json!({}), "threat-model:build", "stride")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn non_pasta_methodology_rejects_stage_selection() {
        let error =
            read_stages(&json!({"stages": ["s1"]}), "threat-model:build", "dread").unwrap_err();
        assert!(error.to_string().contains("PASTA-specific"));
    }
}
