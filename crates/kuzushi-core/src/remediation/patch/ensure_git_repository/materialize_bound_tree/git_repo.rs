use super::manifest::BoundTreeManifest;
use super::*;

pub(super) fn install_minimal_git_repository(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    initialize_repository(checkout, manifest, control, deadline)?;
    hash_materialized_blobs(checkout, manifest, control, deadline)?;
    reconstruct_bound_index(checkout, manifest, control, deadline)?;
    verify_bound_tree(checkout, manifest, control, deadline)?;
    install_bound_commit(checkout, manifest, control, deadline)?;
    set_detached_head(checkout, manifest, control, deadline)?;
    verify_detached_head(checkout, manifest, control, deadline)
}

fn initialize_repository(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let parent = checkout
        .parent()
        .context("patch checkout path has no parent")?;
    let template = tempfile::tempdir_in(parent)
        .context("patch:finding could not create an empty Git template")?;
    let template_arg = format!("--template={}", template.path().display());
    let mut args = vec!["init", "--quiet"];
    if manifest.uses_sha256() {
        args.push("--object-format=sha256");
    }
    args.extend([template_arg.as_str(), "."]);
    let output = run_git_until(
        control,
        deadline,
        checkout,
        &args,
        "git initialize isolated patch checkout",
    )?;
    ensure_git_success(&output, "initialize isolated patch checkout")
}

fn hash_materialized_blobs(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    if manifest.entries.is_empty() {
        return Ok(());
    }
    let paths = manifest.path_request();
    let output = run_git_input_until(
        control,
        deadline,
        checkout,
        &["hash-object", "-w", "--no-filters", "--stdin-paths"],
        &paths,
        "git hash isolated patch blobs",
    )?;
    ensure_git_success(&output, "hash isolated patch blobs")?;
    validate_hashed_blobs(&output.stdout, manifest)
}

fn validate_hashed_blobs(output: &[u8], manifest: &BoundTreeManifest) -> Result<()> {
    anyhow::ensure!(
        output.is_empty() || output.ends_with(b"\n"),
        "patch:finding isolated blob hash output was truncated"
    );
    let hashes = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        hashes.len() == manifest.entries.len(),
        "patch:finding isolated blob hash count did not match the bound tree"
    );
    for (actual, expected) in hashes.iter().zip(&manifest.entries) {
        anyhow::ensure!(
            *actual == expected.oid.as_bytes(),
            "patch:finding materialized blob changed before repository initialization"
        );
    }
    Ok(())
}

fn reconstruct_bound_index(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let empty = run_git_until(
        control,
        deadline,
        checkout,
        &["read-tree", "--empty"],
        "git initialize isolated patch index",
    )?;
    ensure_git_success(&empty, "initialize isolated patch index")?;
    if manifest.entries.is_empty() {
        return Ok(());
    }
    let index = manifest.index_request();
    let output = run_git_input_until(
        control,
        deadline,
        checkout,
        &["update-index", "-z", "--index-info"],
        &index,
        "git reconstruct bound patch index",
    )?;
    ensure_git_success(&output, "reconstruct bound patch index")
}

fn verify_bound_tree(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let output = run_git_until(
        control,
        deadline,
        checkout,
        &["write-tree"],
        "git verify isolated patch tree",
    )?;
    ensure_git_success(&output, "verify isolated patch tree")?;
    let actual = read_oid(&output.stdout, manifest.tree_oid.len(), "isolated tree")?;
    anyhow::ensure!(
        actual == manifest.tree_oid,
        "patch:finding materialized tree did not match the bound commit"
    );
    Ok(())
}

fn install_bound_commit(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let output = run_git_input_until(
        control,
        deadline,
        checkout,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        &manifest.commit_body,
        "git install bound patch commit",
    )?;
    ensure_git_success(&output, "install bound patch commit")?;
    let actual = read_oid(
        &output.stdout,
        manifest.source_commit.len(),
        "isolated commit",
    )?;
    anyhow::ensure!(
        actual == manifest.source_commit,
        "patch:finding isolated commit did not match the authorized object id"
    );
    Ok(())
}

fn set_detached_head(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    if manifest.has_parents() {
        let shallow = checkout.join(".git/shallow");
        crate::fs_atomic::write_atomic_bytes(
            &shallow,
            format!("{}\n", manifest.source_commit).as_bytes(),
        )
        .context("patch:finding could not mark isolated patch history shallow")?;
    }
    let output = run_git_until(
        control,
        deadline,
        checkout,
        &["update-ref", "--no-deref", "HEAD", &manifest.source_commit],
        "git set isolated patch HEAD",
    )?;
    ensure_git_success(&output, "set isolated patch HEAD")
}

fn verify_detached_head(
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let output = run_git_until(
        control,
        deadline,
        checkout,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        "git verify isolated patch HEAD",
    )?;
    ensure_git_success(&output, "verify isolated patch HEAD")?;
    let actual = read_oid(
        &output.stdout,
        manifest.source_commit.len(),
        "isolated HEAD",
    )?;
    anyhow::ensure!(
        actual == manifest.source_commit,
        "patch:finding isolated HEAD did not retain the bound commit"
    );
    verify_bound_tree(checkout, manifest, control, deadline)
}

fn read_oid(bytes: &[u8], expected_len: usize, label: &str) -> Result<String> {
    let oid = std::str::from_utf8(bytes)
        .with_context(|| format!("patch:finding {label} id was not UTF-8"))?
        .trim();
    anyhow::ensure!(
        oid.len() == expected_len && oid.chars().all(|ch| ch.is_ascii_hexdigit()),
        "patch:finding {label} id was invalid"
    );
    Ok(oid.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> BoundTreeManifest {
        BoundTreeManifest {
            source_commit: "2222222222222222222222222222222222222222".to_string(),
            tree_oid: "3333333333333333333333333333333333333333".to_string(),
            commit_body: Vec::new(),
            entries: vec![super::super::manifest::BoundTreeEntry {
                mode: "100755".to_string(),
                oid: "1111111111111111111111111111111111111111".to_string(),
                size: 1,
                git_path: "tool".to_string(),
                relative_path: PathBuf::from("tool"),
            }],
            batch_output_bound: 128,
        }
    }

    #[test]
    fn blob_hash_validation_rejects_missing_duplicate_and_wrong_hashes() {
        let manifest = manifest();
        assert!(validate_hashed_blobs(b"", &manifest).is_err());
        assert!(validate_hashed_blobs(
            b"1111111111111111111111111111111111111111\n1111111111111111111111111111111111111111\n",
            &manifest
        )
        .is_err());
        assert!(
            validate_hashed_blobs(b"9999999999999999999999999999999999999999\n", &manifest)
                .is_err()
        );
        assert!(
            validate_hashed_blobs(b"1111111111111111111111111111111111111111\n", &manifest).is_ok()
        );
    }
}
