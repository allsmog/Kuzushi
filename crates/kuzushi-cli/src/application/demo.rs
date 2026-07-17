use super::scan::scan_command_with_requested_input;
use super::scan_gate::ScanGatePolicy;
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Offline first-wow: write a small vulnerable fixture and scan it with the
/// deterministic engines (secret-scan, iac-scan). No API key, no model, no
/// external scanner binaries — real scanner signals with explicit proof state
/// in seconds, without claiming source-grounded confirmation.
pub(crate) async fn demo_command(json: bool) -> Result<()> {
    let demo_dir = kuzushi_core::prepare_demo_fixture()?;
    if !json {
        eprintln!(
            "demo: scanning a vendored vulnerable fixture at {}",
            demo_dir.display()
        );
        eprintln!("demo: deterministic engines only — nothing leaves this machine.\n");
    }
    scan_command_with_requested_input(
        demo_dir.clone(),
        kuzushi_core::offline_demo_scan_input(),
        kuzushi_core::offline_demo_task_labels(),
        json,
        false,
        ScanGatePolicy::default(),
    )
    .await?;
    if !json {
        print_demo_next_steps(&demo_dir);
    }
    Ok(())
}

fn print_demo_next_steps(demo_dir: &PathBuf) {
    eprint!(
        "{}",
        demo_next_steps(demo_dir, demo_finding_example(demo_dir).as_deref())
    );
}

fn demo_finding_example(demo_dir: &Path) -> Option<String> {
    let workspace = kuzushi_core::WorkspaceTarget::new(demo_dir).ok()?;
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).ok()?;
    let finding = store.list_findings(1).ok()?.into_iter().next()?;
    Some(format!(
        "{} · {} · {}:{} · signal_only",
        finding.severity.as_str().to_ascii_uppercase(),
        finding.title,
        finding.file_path,
        finding.start_line
    ))
}

fn demo_next_steps(demo_dir: &Path, example: Option<&str>) -> String {
    let dir = demo_dir.display();
    let example = example
        .map(|value| format!("demo: example finding: {value}\n"))
        .unwrap_or_default();
    format!(
        "\ndemo: scanner signals were persisted with an honest signal_only proof state\n\
         demo: (not source-grounded proof).\n\
         {example}\
         demo: inspect the temporary fixture:\n\
           cd {dir}\n\
           kuzushi findings --target .\n\
           kuzushi finding F-0001 --target .\n\
           kuzushi suppress F-0001 --target . --reason \"demo\"\n\
         \ndemo: the fixture above is safe to delete anytime.\n\
         demo: ready for your code? Run `kuzushi scan <repo-path>`. To unlock\n\
         demo: triage and verification, launch `kuzushi` and choose a model,\n\
         demo: or set `KUZUSHI_MODEL=provider:model` for the scan command.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_handoff_points_to_persisted_evidence_without_claiming_visible_rows() {
        let message = demo_next_steps(
            Path::new("/tmp/demo-target"),
            Some("HIGH · example · config.env:2 · signal_only"),
        );

        assert!(message.contains("example finding: HIGH · example"));
        assert!(message.contains("cd /tmp/demo-target"));
        assert!(message.contains("kuzushi finding F-0001 --target ."));
        assert!(message.contains("kuzushi scan <repo-path>"));
        assert!(!message.contains("findings above"));
    }
}
