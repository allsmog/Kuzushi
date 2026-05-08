use super::prelude::*;
use super::*;

pub(crate) fn permissions_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
    let target_label = workspace
        .as_ref()
        .map(|workspace| workspace.root().display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let report = serde_json::json!({
        "target": target_label,
        "policy": {
            "modelFallback": "forbidden without explicit operator consent",
            "shellNetworkEgress": "approval required before dispatch",
            "shellFilesystemWrites": "approval required for writes outside .kuzushi or staged patch flows",
            "destructiveActions": "approval required; denial leaves state unchanged",
            "headlessRun": "explicit tool name required; no focused-module shorthand",
            "sandbox": "tools must state backend and risk; validation evidence records backend when available"
        },
        "next": [
            "kuzushi doctor --target .",
            "kuzushi runs list --target ."
        ]
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Kuzushi permissions");
        println!("Target: {}", report["target"].as_str().unwrap_or("none"));
        println!("Model fallback: forbidden without explicit operator consent");
        println!("Shell network egress: approval required before dispatch");
        println!("Shell filesystem writes: approval required outside .kuzushi/staged patch flows");
        println!("Destructive actions: approval required; denial leaves state unchanged");
        println!("Headless run: explicit tool name required; no `run .` shorthand");
        println!("Sandbox: validation evidence records backend when available");
        println!("Next: kuzushi doctor --target .");
    }
    Ok(())
}

pub(crate) fn resolve_persisted_finding(
    store: &FindingStore,
    reference: &str,
    workspace: &WorkspaceTarget,
) -> Result<kuzushi_core::Finding> {
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;
    if let Some(alias_finding) = resolve_finding_alias(&all_findings, reference) {
        return Ok(store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding));
    }
    store.get_finding_by_reference(reference)?.with_context(|| {
        format!(
            "no finding found for {reference:?} at {}\nNext: kuzushi findings --target {}",
            workspace.findings_db_path().display(),
            workspace.root().display()
        )
    })
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn config_command(command: ConfigCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        ConfigCommand::Show => config_show_command(target),
        ConfigCommand::Init { force } => config_init_command(force),
        ConfigCommand::Path => config_path_command(),
    }
}

pub(crate) fn config_show_command(target: Option<PathBuf>) -> Result<()> {
    let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

pub(crate) fn config_init_command(force: bool) -> Result<()> {
    let path = writable_config_init_path(force)?;
    write_default_config(&path)?;
    println!("{}", path.display());
    Ok(())
}

pub(crate) fn writable_config_init_path(force: bool) -> Result<PathBuf> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    let path = paths.global_config_path();
    ensure_config_init_allowed(&path, force)?;
    Ok(path)
}

pub(crate) fn ensure_config_init_allowed(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn config_path_command() -> Result<()> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    println!("{}", paths.global_config_path().display());
    Ok(())
}

pub(crate) fn auth_command(command: AuthCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        AuthCommand::Ping { provider, model } => auth_ping(&provider, model, target),
    }
}
