use crate::tmux_harness::{ArtifactSeed, TmuxSession};
use cucumber::World;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Default, World)]
pub struct OnboardingWorld {
    pub session: Option<TmuxSession>,
    pub env: HashMap<String, String>,
    pub binary: PathBuf,
    pub pending_seeds: Vec<ArtifactSeed>,
    pub terminal_size: Option<(u16, u16)>,
}

impl OnboardingWorld {
    pub fn require_session(&self) -> &TmuxSession {
        self.session
            .as_ref()
            .expect("scenario forgot to launch the shell first")
    }

    pub fn ensure_binary(&mut self) {
        if !self.binary.as_os_str().is_empty() {
            return;
        }
        let bin = std::env::var("KUZUSHI_BIN")
            .ok()
            .map(explicit_kuzushi_binary)
            .unwrap_or_else(built_workspace_binary);
        assert!(
            bin.is_file(),
            "expected kuzushi binary at {}; build with `cargo build -p kuzushi-cli` or set KUZUSHI_BIN",
            bin.display()
        );
        self.binary = bin;
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect("BDD crate must live under the Kuzushi workspace")
}

fn explicit_kuzushi_binary(value: String) -> PathBuf {
    let path = PathBuf::from(value);
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|error| panic!("KUZUSHI_BIN {} is not usable: {error}", path.display()));
    eprintln!(
        "BDD binary provenance: explicit KUZUSHI_BIN={}",
        canonical.display()
    );
    canonical
}

fn built_workspace_binary() -> PathBuf {
    static BUILT_BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILT_BINARY
        .get_or_init(build_workspace_binary)
        .clone()
        .unwrap_or_else(|error| panic!("{error}"))
}

fn build_workspace_binary() -> Result<PathBuf, String> {
    let root = workspace_root();
    let status = Command::new("cargo")
        .args(["build", "-p", "kuzushi-cli", "--bin", "kuzushi"])
        .current_dir(&root)
        .status()
        .map_err(|error| format!("could not build current Kuzushi binary: {error}"))?;
    if !status.success() {
        return Err(format!(
            "building current Kuzushi binary failed with status {status}"
        ));
    }
    let path = workspace_binary_path(&root);
    let canonical = path.canonicalize().map_err(|error| {
        format!(
            "current Kuzushi build did not produce {}: {error}",
            path.display()
        )
    })?;
    eprintln!(
        "BDD binary provenance: freshly built workspace binary {}",
        canonical.display()
    );
    Ok(canonical)
}

fn workspace_binary_path(root: &std::path::Path) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    target.join("debug/kuzushi")
}
