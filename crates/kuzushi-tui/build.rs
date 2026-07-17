//! Embed build provenance (git sha, dirty flag, profile) so a published
//! release binary and a working-tree build are distinguishable at runtime
//! (`kuzushi --version`, the `/config` view). Builds outside a git checkout
//! (published tarballs) fall back to "unknown" rather than failing.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let sha = git(&["rev-parse", "--short=9", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = git(&["status", "--porcelain"])
        .map(|out| !out.is_empty())
        .unwrap_or(false);
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=KUZUSHI_BUILD_GIT_SHA={sha}");
    println!(
        "cargo:rustc-env=KUZUSHI_BUILD_GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );
    println!("cargo:rustc-env=KUZUSHI_BUILD_PROFILE={profile}");
    emit_git_rerun_paths();
}

fn emit_git_rerun_paths() {
    let Some(git_dir) = git_path(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    // A symbolic HEAD file does not change when its branch advances. Watch the
    // resolved branch ref too; the common dir keeps this correct in worktrees.
    let common_dir = git_path(&["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .unwrap_or_else(|| git_dir.clone());
    emit_rerun_path(&git_dir.join("HEAD"));
    emit_rerun_path(&common_dir.join("packed-refs"));
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        emit_rerun_path(&common_dir.join(head_ref));
    }
}

fn git_path(args: &[&str]) -> Option<PathBuf> {
    git(args).map(PathBuf::from)
}

fn emit_rerun_path(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
