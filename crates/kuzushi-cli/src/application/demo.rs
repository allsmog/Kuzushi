use super::scan::scan_command_with_requested_input;
use super::scan_gate::ScanGatePolicy;
use anyhow::Result;
use std::path::PathBuf;

/// Offline first-wow: write a small vulnerable fixture and scan it with the
/// deterministic engines (secret-scan, iac-scan). No API key, no model, no
/// external scanner binaries — a real finding with evidence in seconds.
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
    let dir = demo_dir.display();
    eprintln!("\ndemo: every finding above carries evidence and a proof state. Next:");
    eprintln!("  kuzushi findings --target {dir}");
    eprintln!("  kuzushi finding F-0001 --target {dir}");
    eprintln!("  kuzushi suppress F-0001 --target {dir} --reason \"demo\"");
    eprintln!("\ndemo: the fixture lives at {dir} — safe to delete anytime.");
    eprintln!("demo: point `kuzushi scan` at a real repo when ready; add a model");
    eprintln!("demo: (`kuzushi config init`) to unlock triage and verification.");
}
