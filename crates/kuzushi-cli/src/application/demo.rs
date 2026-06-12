use super::scan::scan_command;
use super::scan_gate::ScanGatePolicy;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

/// Offline first-wow: write a small vulnerable fixture and scan it with the
/// deterministic engines (secret-scan, iac-scan). No API key, no model, no
/// external scanner binaries — a real finding with evidence in seconds.
pub(crate) async fn demo_command(json: bool) -> Result<()> {
    let demo_dir = prepare_demo_fixture()?;
    if !json {
        eprintln!("demo: scanning a vendored vulnerable fixture at {}", demo_dir.display());
        eprintln!("demo: deterministic engines only — nothing leaves this machine.\n");
    }
    scan_command(
        demo_dir.clone(),
        None,
        vec!["secret-scan".to_string(), "iac-scan".to_string()],
        None,
        json,
        false,
        None,
        None,
        false,
        ScanGatePolicy::default(),
    )
    .await?;
    if !json {
        print_demo_next_steps(&demo_dir);
    }
    Ok(())
}

fn prepare_demo_fixture() -> Result<PathBuf> {
    let demo_dir = std::env::temp_dir().join("kuzushi-demo");
    // Recreate from scratch so repeat runs stay deterministic.
    if demo_dir.exists() {
        fs::remove_dir_all(&demo_dir)
            .with_context(|| format!("could not reset {}", demo_dir.display()))?;
    }
    fs::create_dir_all(&demo_dir)
        .with_context(|| format!("could not create {}", demo_dir.display()))?;
    fs::write(
        demo_dir.join("config.env"),
        "# production credentials accidentally committed\n\
         AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         AWS_SECRET_ACCESS_KEY=wJalrXUtnFE/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
         GITHUB_TOKEN=ghp_x7rT9qLm2KvW8pYzN3jBdF5cH1aG6eQ4sU0i\n",
    )?;
    fs::write(
        demo_dir.join("Dockerfile"),
        "FROM node:latest\n\
         ADD https://example.com/setup.sh /setup.sh\n\
         COPY . .\n\
         RUN npm install\n\
         CMD [\"node\", \"server.js\"]\n",
    )?;
    Ok(demo_dir)
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
