use super::*;

pub(crate) fn build_patch_prompt(
    repo_root: &Path,
    repo_name: &str,
    finding: &Finding,
    triage: &TriageOutcome,
    history: &[PatchAttempt],
    style: PatchStyle,
) -> Result<String> {
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let triage_json = serde_json::to_string_pretty(triage).context("Could not serialize triage")?;
    let source_body = read_source_context(repo_root, &finding.file_path)?;
    let source_context =
        crate::prompts::render_untrusted_many(&[(finding.file_path.clone(), source_body)]);
    let history_block = if history.is_empty() {
        "No previous patch attempts.".to_string()
    } else {
        history
            .iter()
            .map(|attempt| {
                format!(
                    "### Attempt {} - {}\nDiff:\n```diff\n{}\n```\nValidator output:\n{}",
                    attempt.attempt,
                    attempt.status.as_str(),
                    attempt.diff,
                    attempt.output
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    Ok(format!(
        "Generate a unified diff that fixes this confirmed security finding.\n\
         {style_instruction}\n\
         The diff must apply with `git apply` from the repository root and use a/ and b/ paths.\n\n\
         ## Repository\n{repo_name}\n\n\
         ## Finding JSON\n{finding_json}\n\n\
         ## Triage JSON\n{triage_json}\n\n\
         ## Vulnerable Source Context\n{source_context}\n\n\
         ## Previous Attempts\n{history_block}\n\n\
         ## Output\nReturn only a JSON object with string fields `diff` and `explanation`.",
        style_instruction = style.prompt_instruction(),
    ))
}

pub(crate) fn read_source_context(repo_root: &Path, file_path: &str) -> Result<String> {
    let path = repo_root.join(file_path);
    let Ok(raw) = fs::read_to_string(&path) else {
        return Ok(format!(
            "Could not read {}; produce a patch from the finding metadata.",
            file_path
        ));
    };
    let max_bytes = 40_000usize;
    let content = if raw.len() > max_bytes {
        let cutoff = raw
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= max_bytes)
            .last()
            .unwrap_or(0);
        format!("{}\n... [truncated]", &raw[..cutoff])
    } else {
        raw
    };
    Ok(content)
}

pub(crate) fn parse_patch_synthesis(raw: Value) -> Result<PatchSynthesis> {
    let Value::Object(object) = raw else {
        anyhow::bail!("patch synthesis output parse failed: expected a JSON object");
    };
    let diff = read_object_raw_string(&object, &["diff"])
        .context("patch synthesis output parse failed: missing non-empty diff")?;
    let explanation = read_object_string(&object, &["explanation"]).unwrap_or_default();
    Ok(PatchSynthesis { diff, explanation })
}

#[derive(Debug, Clone)]
pub(crate) struct ValidationResult {
    pub(crate) status: PatchStatus,
    pub(crate) output: String,
}
