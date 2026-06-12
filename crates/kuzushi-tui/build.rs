//! Embed build provenance (git sha, dirty flag, profile) so a published
//! release binary and a working-tree build are distinguishable at runtime
//! (`kuzushi --version`, the `/config` view). Builds outside a git checkout
//! (published tarballs) fall back to "unknown" rather than failing.

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
    // Refresh the sha on commit/checkout. The dirty flag is inherently a
    // snapshot of the tree at build time — any edit after the build stales
    // the binary regardless, so we don't chase every file change.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
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
