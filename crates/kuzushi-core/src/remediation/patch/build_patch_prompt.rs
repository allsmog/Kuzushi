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
    let Ok(path) = crate::code_nav::canonicalise_within(repo_root, file_path) else {
        return Ok(format!(
            "Could not read {}; produce a patch from the finding metadata.",
            file_path
        ));
    };
    let Ok(source) = crate::bounded_file::read_utf8_text_prefix(&path, 40_000) else {
        return Ok(format!(
            "Could not read {}; produce a patch from the finding metadata.",
            file_path
        ));
    };
    Ok(if source.truncated {
        format!("{}\n... [truncated]", source.text)
    } else {
        source.text
    })
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

#[cfg(test)]
mod bounded_source_context_tests {
    use super::read_source_context;
    use std::fs;

    #[test]
    fn source_context_rejects_repository_escape() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(temp.path().join("secret.rs"), "outside secret").unwrap();

        let context = read_source_context(&repo, "../secret.rs").unwrap();

        assert!(context.contains("Could not read"));
        assert!(!context.contains("outside secret"));
    }

    #[test]
    fn source_context_reads_only_the_bounded_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("huge.rs");
        fs::write(&path, "fn vulnerable() {}\n").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();

        let context = read_source_context(temp.path(), "huge.rs").unwrap();

        assert!(context.starts_with("fn vulnerable"));
        assert!(context.ends_with("... [truncated]"));
        assert!(context.len() < 41_000);
    }
}
