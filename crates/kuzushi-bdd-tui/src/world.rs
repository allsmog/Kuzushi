use crate::tmux_harness::TmuxSession;
use cucumber::World;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, World)]
pub struct OnboardingWorld {
    pub session: Option<TmuxSession>,
    pub env: HashMap<String, String>,
    pub binary: PathBuf,
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
            .map(PathBuf::from)
            .unwrap_or_else(default_kuzushi_binary);
        assert!(
            bin.is_file(),
            "expected kuzushi binary at {}; build with `cargo build -p kuzushi-cli` or set KUZUSHI_BIN",
            bin.display()
        );
        self.binary = bin;
    }
}

fn default_kuzushi_binary() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/kuzushi-bdd-tui; the binary
    // lives in the workspace's shared target/ directory.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("target/debug/kuzushi"))
        .unwrap_or_else(|| PathBuf::from("target/debug/kuzushi"))
}
