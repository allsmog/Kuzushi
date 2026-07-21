use super::llm_audit::load_run_trace_audit;
use super::{RunEnvFingerprint, RunHouseRuleFingerprint, RunPromptOverrideFingerprint, RunSummary};
use crate::workspace::target_git_metadata;
use std::fs;
use std::path::Path;

const MAX_PROVENANCE_MARKDOWN_BYTES: usize = 1024 * 1024;
const MAX_THREAT_MODEL_DIGEST_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn summary_with_dynamic_metadata(target: &Path, summary: &RunSummary) -> RunSummary {
    let summary = summary_with_house_rules(target, summary.clone());
    let summary = summary_with_prompt_overrides(target, summary);
    let summary = summary_with_threat_model_digest(target, summary);
    let summary = summary_with_env_fingerprint(summary);
    let summary = summary_with_cli_args(summary);
    let summary = summary_with_target_git(target, summary);
    summary_with_trace_metadata(target, &summary)
}

pub(crate) fn summary_with_trace_metadata(target: &Path, summary: &RunSummary) -> RunSummary {
    summary_with_llm_audit(target, summary.clone())
}

fn summary_with_llm_audit(target: &Path, summary: RunSummary) -> RunSummary {
    let audit = load_run_trace_audit(target, &summary.run_id);
    let mut summary = summary;
    if !audit.llm_calls.is_empty() {
        summary = summary.with_llm_calls(audit.llm_calls);
    }
    if audit.malformed_lines > 0 {
        summary = summary.with_trace_malformed_lines(Some(audit.malformed_lines));
    }
    summary
}

fn summary_with_house_rules(target: &Path, summary: RunSummary) -> RunSummary {
    let house_rules = load_house_rule_fingerprints(target);
    if house_rules.is_empty() {
        return summary;
    }
    summary.with_house_rules(house_rules)
}

fn summary_with_prompt_overrides(target: &Path, summary: RunSummary) -> RunSummary {
    let prompt_overrides = load_prompt_override_fingerprints(target);
    if prompt_overrides.is_empty() {
        return summary;
    }
    summary.with_prompt_overrides(prompt_overrides)
}

fn summary_with_threat_model_digest(target: &Path, summary: RunSummary) -> RunSummary {
    let summary = summary_with_threat_model_provenance(target, summary);
    if let Some(hash) = threat_model_sha256(target) {
        return summary.with_threat_model_sha256(Some(hash));
    }
    summary
}

/// Record which document governs this target and via which resolution step
/// (scope file, ancestor file, or the persistent model), so review can
/// answer "which model seeded this run".
fn summary_with_threat_model_provenance(target: &Path, summary: RunSummary) -> RunSummary {
    let Some(resolved) =
        crate::capabilities::threat_model::resolve_threat_model(target, ".")
    else {
        return summary;
    };
    summary.with_threat_model_provenance(
        Some(resolved.source_path.to_string_lossy().into_owned()),
        Some(resolved.resolved_via.as_str().to_string()),
    )
}

fn summary_with_env_fingerprint(summary: RunSummary) -> RunSummary {
    if !summary.env_fingerprint.is_empty() {
        return summary;
    }
    let fingerprint = collect_env_fingerprints(std::env::vars());
    if fingerprint.is_empty() {
        return summary;
    }
    summary.with_env_fingerprint(fingerprint)
}

fn summary_with_cli_args(summary: RunSummary) -> RunSummary {
    if !summary.cli_args.is_empty() {
        return summary;
    }
    let args = collect_cli_args(std::env::args());
    if args.is_empty() {
        return summary;
    }
    summary.with_cli_args(args)
}

fn summary_with_target_git(target: &Path, summary: RunSummary) -> RunSummary {
    if summary.target_git.is_some() {
        return summary;
    }
    summary.with_target_git(target_git_metadata(target))
}

fn collect_cli_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut redact_next = false;
    args.into_iter()
        .take(64)
        .map(|arg| cli_arg_for_record(arg, &mut redact_next))
        .collect()
}

fn cli_arg_for_record(arg: String, redact_next: &mut bool) -> String {
    if std::mem::take(redact_next) {
        return "<redacted>".to_string();
    }
    let arg = truncate_cli_arg(arg);
    if sensitive_cli_assignment(&arg) {
        return redact_assignment(&arg);
    }
    if sensitive_cli_flag(&arg) {
        *redact_next = true;
    }
    arg
}

fn truncate_cli_arg(arg: String) -> String {
    const MAX_ARG_LEN: usize = 512;
    if arg.chars().count() <= MAX_ARG_LEN {
        return arg;
    }
    arg.chars().take(MAX_ARG_LEN).collect()
}

fn sensitive_cli_assignment(arg: &str) -> bool {
    arg.split_once('=')
        .is_some_and(|(key, _)| sensitive_arg_key(key))
}

fn sensitive_cli_flag(arg: &str) -> bool {
    !arg.contains('=') && sensitive_arg_key(arg)
}

fn sensitive_arg_key(key: &str) -> bool {
    let normalized = key
        .trim_start_matches('-')
        .replace('_', "-")
        .to_ascii_uppercase();
    [
        "API-KEY",
        "AUTH-TOKEN",
        "OAUTH-TOKEN",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn redact_assignment(arg: &str) -> String {
    let Some((key, _)) = arg.split_once('=') else {
        return "<redacted>".to_string();
    };
    format!("{key}=<redacted>")
}

fn collect_env_fingerprints(
    vars: impl IntoIterator<Item = (String, String)>,
) -> Vec<RunEnvFingerprint> {
    let mut fingerprints = vars
        .into_iter()
        .filter(|(key, _)| should_record_env_key(key))
        .map(env_fingerprint)
        .collect::<Vec<_>>();
    fingerprints.sort_by(|left, right| left.key.cmp(&right.key));
    fingerprints
}

fn env_fingerprint((key, value): (String, String)) -> RunEnvFingerprint {
    let fingerprint = if sensitive_env_key(&key) {
        "<set>".to_string()
    } else {
        value_sha256(&value)
    };
    RunEnvFingerprint { key, fingerprint }
}

fn should_record_env_key(key: &str) -> bool {
    key.starts_with("KUZUSHI_")
        || key.ends_with("_API_KEY")
        || key.ends_with("_AUTH_TOKEN")
        || key.ends_with("_OAUTH_TOKEN")
}

fn sensitive_env_key(key: &str) -> bool {
    ["KEY", "TOKEN", "SECRET", "CREDENTIAL", "PASSWORD"]
        .iter()
        .any(|part| key.contains(part))
}

fn threat_model_sha256(target: &Path) -> Option<String> {
    let path = crate::capabilities::threat_model::persistent_threat_model_path(target);
    bounded_file_sha256(target, &path, MAX_THREAT_MODEL_DIGEST_BYTES)
}

fn load_prompt_override_fingerprints(target: &Path) -> Vec<RunPromptOverrideFingerprint> {
    let dir = crate::options::prompt_overrides_root(target);
    let modules = match read_provenance_dir(target, &dir) {
        Ok(Some(entries)) => entries,
        Ok(None) => return Vec::new(),
        Err(sha256) => return vec![invalid_prompt_root_fingerprint(sha256)],
    };
    let mut fingerprints = modules
        .flatten()
        .flat_map(|entry| prompt_module_fingerprints(target, entry))
        .collect::<Vec<_>>();
    fingerprints.sort_by(prompt_override_order);
    fingerprints
}

fn prompt_module_fingerprints(
    target: &Path,
    entry: fs::DirEntry,
) -> Vec<RunPromptOverrideFingerprint> {
    let path = entry.path();
    let Some(module) = entry.file_name().to_str().map(str::to_string) else {
        return Vec::new();
    };
    match read_provenance_dir(target, &path) {
        Ok(Some(entries)) => prompt_override_fingerprints(target, &module, entries),
        Ok(None) => Vec::new(),
        Err(sha256) => vec![invalid_prompt_module_fingerprint(&module, sha256)],
    }
}

fn prompt_override_fingerprints(
    target: &Path,
    module: &str,
    entries: fs::ReadDir,
) -> Vec<RunPromptOverrideFingerprint> {
    entries
        .flatten()
        .filter_map(|entry| prompt_override_fingerprint(target, module, entry))
        .collect()
}

fn prompt_override_fingerprint(
    target: &Path,
    module: &str,
    entry: fs::DirEntry,
) -> Option<RunPromptOverrideFingerprint> {
    let path = entry.path();
    let verb = path.file_stem()?.to_str()?.to_string();
    let sha256 = markdown_artifact_sha256(target, &path)?;
    Some(RunPromptOverrideFingerprint {
        module: module.to_string(),
        verb: verb.clone(),
        path: prompt_override_relative_path(module, &verb),
        sha256,
    })
}

fn prompt_override_order(
    left: &RunPromptOverrideFingerprint,
    right: &RunPromptOverrideFingerprint,
) -> std::cmp::Ordering {
    left.module
        .cmp(&right.module)
        .then_with(|| left.verb.cmp(&right.verb))
}

fn load_house_rule_fingerprints(target: &Path) -> Vec<RunHouseRuleFingerprint> {
    let dir = crate::options::house_rules_root(target);
    let entries = match read_provenance_dir(target, &dir) {
        Ok(Some(entries)) => entries,
        Ok(None) => return Vec::new(),
        Err(sha256) => return vec![invalid_house_rule_root_fingerprint(sha256)],
    };
    let mut fingerprints = entries
        .flatten()
        .filter_map(|entry| house_rule_fingerprint(target, entry))
        .collect::<Vec<_>>();
    fingerprints.sort_by(|left, right| left.module.cmp(&right.module));
    fingerprints
}

fn house_rule_fingerprint(target: &Path, entry: fs::DirEntry) -> Option<RunHouseRuleFingerprint> {
    let path = entry.path();
    let file_name = path.file_name()?.to_str()?.to_string();
    let sha256 = markdown_artifact_sha256(target, &path)?;
    Some(RunHouseRuleFingerprint {
        module: path.file_stem()?.to_str()?.to_string(),
        path: house_rule_relative_path(&file_name),
        sha256,
    })
}

fn markdown_artifact_sha256(target: &Path, path: &Path) -> Option<String> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
        return None;
    }
    bounded_file_sha256(target, path, MAX_PROVENANCE_MARKDOWN_BYTES)
}

fn read_provenance_dir(target: &Path, dir: &Path) -> Result<Option<fs::ReadDir>, &'static str> {
    match crate::bounded_file::read_dir_within(target, dir) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            Err("invalid:not-a-directory")
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err("invalid:unsafe-path")
        }
        Err(_) => Err("invalid:unreadable"),
    }
}

fn invalid_house_rule_root_fingerprint(sha256: &str) -> RunHouseRuleFingerprint {
    RunHouseRuleFingerprint {
        module: "<house-rules>".to_string(),
        path: crate::options::relative_house_rules_root()
            .display()
            .to_string(),
        sha256: sha256.to_string(),
    }
}

fn invalid_prompt_root_fingerprint(sha256: &str) -> RunPromptOverrideFingerprint {
    RunPromptOverrideFingerprint {
        module: "<prompts>".to_string(),
        verb: "<root>".to_string(),
        path: crate::options::relative_prompt_overrides_root()
            .display()
            .to_string(),
        sha256: sha256.to_string(),
    }
}

fn invalid_prompt_module_fingerprint(module: &str, sha256: &str) -> RunPromptOverrideFingerprint {
    RunPromptOverrideFingerprint {
        module: module.to_string(),
        verb: "<module>".to_string(),
        path: crate::options::relative_module_prompt_root(module)
            .display()
            .to_string(),
        sha256: sha256.to_string(),
    }
}

fn bounded_file_sha256(target: &Path, path: &Path, max_bytes: usize) -> Option<String> {
    match crate::bounded_file::read_regular_bytes_within(target, path, max_bytes) {
        Ok(bytes) => Some(bytes_sha256(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            Some("invalid:not-a-file".to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Some("invalid:unsafe-path".to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            Some("invalid:oversized".to_string())
        }
        Err(_) => Some("invalid:unreadable".to_string()),
    }
}

fn value_sha256(value: &str) -> String {
    bytes_sha256(value.as_bytes())
}

fn bytes_sha256(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(bytes)
    )
}

fn house_rule_relative_path(file_name: &str) -> String {
    crate::options::relative_house_rules_root()
        .join(file_name)
        .display()
        .to_string()
}

fn prompt_override_relative_path(module: &str, verb: &str) -> String {
    crate::options::relative_prompt_override_path(module, verb)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_fingerprint_hashes_values_and_redacts_secret_values() {
        let fingerprints = collect_env_fingerprints([
            ("KUZUSHI_DEBUG".to_string(), "1".to_string()),
            ("OPENAI_API_KEY".to_string(), "sk-secret".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ]);

        assert_eq!(fingerprints.len(), 2);
        assert_eq!(fingerprints[0].key, "KUZUSHI_DEBUG");
        assert!(fingerprints[0].fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprints[1].key, "OPENAI_API_KEY");
        assert_eq!(fingerprints[1].fingerprint, "<set>");
    }

    #[test]
    fn cli_args_are_bounded_and_redact_sensitive_values() {
        let long_arg = "x".repeat(600);
        let args = collect_cli_args([
            "kuzushi".to_string(),
            "run".to_string(),
            "--api-key=secret".to_string(),
            "--token".to_string(),
            "secret-token".to_string(),
            long_arg,
        ]);

        assert_eq!(args[0], "kuzushi");
        assert_eq!(args[2], "--api-key=<redacted>");
        assert_eq!(args[3], "--token");
        assert_eq!(args[4], "<redacted>");
        assert_eq!(args[5].len(), 512);
    }

    #[cfg(unix)]
    #[test]
    fn prompt_and_house_rule_fingerprints_reject_outside_symlinks() {
        const OUTSIDE_TOKEN: &str = "OUTSIDE-PROVENANCE-TOKEN-MUST-NOT-HASH";
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_module = outside.path().join("triage");
        fs::create_dir_all(&outside_module).unwrap();
        fs::write(outside_module.join("run.md"), OUTSIDE_TOKEN).unwrap();
        let prompt_root = crate::options::prompt_overrides_root(target.path());
        fs::create_dir_all(&prompt_root).unwrap();
        std::os::unix::fs::symlink(&outside_module, prompt_root.join("triage")).unwrap();

        let outside_rule = outside.path().join("rule.md");
        fs::write(&outside_rule, OUTSIDE_TOKEN).unwrap();
        let house_root = crate::options::house_rules_root(target.path());
        fs::create_dir_all(&house_root).unwrap();
        std::os::unix::fs::symlink(&outside_rule, house_root.join("triage.md")).unwrap();

        let prompts = load_prompt_override_fingerprints(target.path());
        let rules = load_house_rule_fingerprints(target.path());
        let serialized = serde_json::to_string(&(&prompts, &rules)).unwrap();

        assert_eq!(prompts[0].sha256, "invalid:unsafe-path");
        assert_eq!(rules[0].sha256, "invalid:unsafe-path");
        assert!(!serialized.contains(OUTSIDE_TOKEN));
        assert!(!serialized.contains(&bytes_sha256(OUTSIDE_TOKEN.as_bytes())));
    }

    #[test]
    fn oversized_prompt_fingerprint_is_explicitly_invalid() {
        let target = tempfile::tempdir().unwrap();
        let path = crate::options::prompt_override_path(target.path(), "triage", "run");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "prompt").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_PROVENANCE_MARKDOWN_BYTES as u64 + 1)
            .unwrap();

        let prompts = load_prompt_override_fingerprints(target.path());

        assert_eq!(prompts[0].sha256, "invalid:oversized");
    }
}
