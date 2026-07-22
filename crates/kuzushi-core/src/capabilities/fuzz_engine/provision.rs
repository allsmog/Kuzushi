//! Pinned auto-provisioning of the agentic-fuzz-engine checkout.
//!
//! When the operator does not pass `afeRepo`, the fuzz tools fetch the pinned
//! engine revision into a content-addressed cache directory outside the
//! scanned repository. The pin lives here (in kuzushi), so engine upgrades are
//! deliberate: bump `DEFAULT_AFE_REV` or pass `afeRev` explicitly. Same rev →
//! same directory → the clone happens at most once per machine.

use super::engine_cli::afe_repo_is_valid;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const DEFAULT_AFE_GIT_URL: &str = "git@github.com:allsmog/agentic-fuzz-engine.git";
/// Remote tip as of 2026-07-22; carries every verb the fuzz module drives
/// (workspace-init, sink-scan, target-generate, target-build,
/// campaign-round-run, finding-impact) plus the fork-scan/entry-scan
/// discovery verbs and the discovery lanes (sanitizer-build/sanitizer-sweep,
/// differential-run, candidate scoring).
pub const DEFAULT_AFE_REV: &str = "c28bb8d4ca7cbb008f9057af50ef4779d6771252";

/// Everything one provisioning attempt needs, resolved by the module layer.
#[derive(Debug, Clone)]
pub struct ProvisionSpec {
    pub git_url: String,
    /// Full 40-hex commit sha — fetch-by-sha needs the complete object id.
    pub rev: String,
    /// Optional deploy key when the ambient ssh config cannot reach the
    /// engine remote (becomes a Rust-built GIT_SSH_COMMAND, never shell text
    /// from the operator).
    pub ssh_key: Option<PathBuf>,
    /// Cache parent, conventionally `~/.cache/agentic-fuzz`.
    pub cache_home: PathBuf,
    pub step_timeout: Duration,
}

pub fn engine_cache_dir(cache_home: &Path, rev: &str) -> PathBuf {
    cache_home.join(format!("engine-{}", &rev[..8.min(rev.len())]))
}

pub fn validate_rev(rev: &str) -> Result<()> {
    let full_lower_hex = rev.len() == 40
        && rev
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    anyhow::ensure!(
        full_lower_hex,
        "afeRev must be a full 40-character lowercase commit sha \
         (shallow fetch-by-sha requires the complete object id); got {rev:?}"
    );
    Ok(())
}

/// Reuse the cached checkout when present, otherwise clone the pinned rev
/// into a staging directory and atomically rename it into place. A
/// half-fetched staging dir can therefore never be mistaken for a usable
/// engine, and a killed attempt leaves nothing the next attempt trips over.
pub fn provision_engine(spec: &ProvisionSpec) -> Result<PathBuf> {
    validate_rev(&spec.rev)?;
    let dest = engine_cache_dir(&spec.cache_home, &spec.rev);
    if afe_repo_is_valid(&dest) {
        return Ok(dest);
    }
    let staging = staging_dir(&dest);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .with_context(|| format!("creating engine staging dir {}", staging.display()))?;
    if let Err(error) = clone_pinned_rev(spec, &staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    publish(&staging, &dest)
}

fn staging_dir(dest: &Path) -> PathBuf {
    // pid-suffixed so a crashed earlier attempt never blocks this one
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("engine");
    dest.with_file_name(format!(".{name}.staging-{}", std::process::id()))
}

fn clone_pinned_rev(spec: &ProvisionSpec, staging: &Path) -> Result<()> {
    run_git(spec, staging, &["init", "--quiet", "."])?;
    run_git(
        spec,
        staging,
        &["fetch", "--quiet", "--depth", "1", &spec.git_url, &spec.rev],
    )?;
    run_git(
        spec,
        staging,
        &["-c", "advice.detachedHead=false", "checkout", "--quiet", &spec.rev],
    )?;
    anyhow::ensure!(
        afe_repo_is_valid(staging),
        "engine rev {} fetched from {} is not an agentic-fuzz-engine checkout \
         (missing src/agentic_fuzz_engine/cli.py)",
        spec.rev,
        spec.git_url,
    );
    Ok(())
}

fn run_git(spec: &ProvisionSpec, cwd: &Path, args: &[&str]) -> Result<()> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(key) = &spec.ssh_key {
        command.env("GIT_SSH_COMMAND", ssh_command_for(key));
    }
    let output = crate::bounded_subprocess::output_with_control(
        &mut command,
        "afe-provision git",
        None,
        spec.step_timeout,
    )?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed while provisioning the engine: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// GIT_SSH_COMMAND is split with shell rules by git, so the key path is
/// single-quoted; BatchMode keeps a bad key a fast error instead of a prompt.
fn ssh_command_for(key: &Path) -> String {
    let quoted = key.display().to_string().replace('\'', r"'\''");
    format!("ssh -i '{quoted}' -o IdentitiesOnly=yes -o BatchMode=yes")
}

fn publish(staging: &Path, dest: &Path) -> Result<PathBuf> {
    match std::fs::rename(staging, dest) {
        Ok(()) => Ok(dest.to_path_buf()),
        // Benign race: a concurrent provision of the same rev won the rename.
        Err(_) if afe_repo_is_valid(dest) => {
            let _ = std::fs::remove_dir_all(staging);
            Ok(dest.to_path_buf())
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(staging);
            Err(error)
                .with_context(|| format!("publishing engine checkout to {}", dest.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(cwd: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A minimal local "engine remote" the provisioner can fetch by sha from.
    fn fixture_engine_remote(dir: &Path, with_cli: bool) -> String {
        if with_cli {
            std::fs::create_dir_all(dir.join("src/agentic_fuzz_engine")).unwrap();
            std::fs::write(dir.join("src/agentic_fuzz_engine/cli.py"), "pass\n").unwrap();
        } else {
            std::fs::write(dir.join("README.md"), "not the engine\n").unwrap();
        }
        git(dir, &["init", "--quiet", "."]);
        git(dir, &["add", "."]);
        git(
            dir,
            &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "--quiet", "-m", "engine"],
        );
        git(dir, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(dir)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn spec(remote: &Path, rev: &str, cache_home: &Path) -> ProvisionSpec {
        ProvisionSpec {
            git_url: remote.display().to_string(),
            rev: rev.to_string(),
            ssh_key: None,
            cache_home: cache_home.to_path_buf(),
            step_timeout: Duration::from_secs(60),
        }
    }

    #[test]
    fn rev_validation_accepts_only_full_lowercase_shas() {
        validate_rev("d480b9429c7889b9692ccb062ee624dd23ba36ec").unwrap();
        for bad in ["d480b94", "", "D480B9429C7889B9692CCB062EE624DD23BA36EC",
                    "z480b9429c7889b9692ccb062ee624dd23ba36ec"] {
            assert!(validate_rev(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn cache_dir_is_content_addressed_by_rev_prefix() {
        let dir = engine_cache_dir(Path::new("/home/op/.cache/agentic-fuzz"), DEFAULT_AFE_REV);
        assert_eq!(
            dir,
            PathBuf::from("/home/op/.cache/agentic-fuzz/engine-c28bb8d4")
        );
    }

    #[test]
    fn provision_clones_once_then_reuses_without_touching_the_remote() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        let rev = fixture_engine_remote(&remote, true);
        let cache = temp.path().join("cache");

        let provisioned = provision_engine(&spec(&remote, &rev, &cache)).unwrap();
        assert!(afe_repo_is_valid(&provisioned));
        assert_eq!(provisioned, engine_cache_dir(&cache, &rev));

        // Second call must reuse the cache: a dead remote proves no fetch ran.
        let dead = spec(Path::new("/nonexistent/remote"), &rev, &cache);
        assert_eq!(provision_engine(&dead).unwrap(), provisioned);
    }

    #[test]
    fn failed_provision_leaves_no_staging_residue_and_no_dest() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let missing_rev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let remote = temp.path().join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        fixture_engine_remote(&remote, true);

        let error = provision_engine(&spec(&remote, missing_rev, &cache)).unwrap_err();
        assert!(format!("{error:#}").contains("git fetch"), "{error:#}");

        let leftovers: Vec<_> = std::fs::read_dir(&cache)
            .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "residue: {leftovers:?}");
    }

    #[test]
    fn a_remote_without_the_engine_layout_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let remote = temp.path().join("remote");
        std::fs::create_dir_all(&remote).unwrap();
        let rev = fixture_engine_remote(&remote, false);
        let cache = temp.path().join("cache");

        let error = provision_engine(&spec(&remote, &rev, &cache)).unwrap_err();
        assert!(
            format!("{error:#}").contains("not an agentic-fuzz-engine checkout"),
            "{error:#}"
        );
        assert!(!engine_cache_dir(&cache, &rev).exists());
    }

    #[test]
    fn ssh_key_paths_are_single_quoted_into_the_ssh_command() {
        let command = ssh_command_for(Path::new("/keys/it's here/id"));
        assert_eq!(
            command,
            r"ssh -i '/keys/it'\''s here/id' -o IdentitiesOnly=yes -o BatchMode=yes"
        );
    }
}
