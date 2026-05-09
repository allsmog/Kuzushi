use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use std::path::PathBuf;

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
