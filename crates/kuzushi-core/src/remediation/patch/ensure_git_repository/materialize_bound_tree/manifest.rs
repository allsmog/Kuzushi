use super::*;
mod parse;

use self::parse::parse_tree_listing;

#[derive(Clone, Debug)]
pub(super) struct BoundTreeEntry {
    pub(super) mode: String,
    pub(super) oid: String,
    pub(super) size: u64,
    pub(super) git_path: String,
    pub(super) relative_path: PathBuf,
}

impl BoundTreeEntry {
    pub(super) fn executable(&self) -> bool {
        self.mode == "100755"
    }
}

pub(super) struct BoundTreeManifest {
    pub(super) source_commit: String,
    pub(super) tree_oid: String,
    pub(super) commit_body: Vec<u8>,
    pub(super) entries: Vec<BoundTreeEntry>,
    pub(super) batch_output_bound: u64,
}

impl BoundTreeManifest {
    pub(super) fn batch_request(&self) -> Vec<u8> {
        let mut request = Vec::new();
        for entry in &self.entries {
            request.extend_from_slice(entry.oid.as_bytes());
            request.push(b'\n');
        }
        request
    }

    pub(super) fn path_request(&self) -> Vec<u8> {
        let mut request = Vec::new();
        for entry in &self.entries {
            request.extend_from_slice(entry.git_path.as_bytes());
            request.push(b'\n');
        }
        request
    }

    pub(super) fn index_request(&self) -> Vec<u8> {
        let mut request = Vec::new();
        for entry in &self.entries {
            request.extend_from_slice(entry.mode.as_bytes());
            request.push(b' ');
            request.extend_from_slice(entry.oid.as_bytes());
            request.push(b'\t');
            request.extend_from_slice(entry.git_path.as_bytes());
            request.push(0);
        }
        request
    }

    pub(super) fn batch_output_bound(&self) -> u64 {
        self.batch_output_bound
    }

    pub(super) fn uses_sha256(&self) -> bool {
        self.source_commit.len() == 64
    }

    pub(super) fn has_parents(&self) -> bool {
        self.commit_body
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty())
            .any(|line| line.starts_with(b"parent "))
    }
}

pub(super) fn load_bound_tree_manifest(
    repo_root: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
    deadline: Instant,
    limits: MaterializationLimits,
    case_insensitive: bool,
) -> Result<BoundTreeManifest> {
    validate_source_commit(source_commit)?;
    let listing = run_git_until(
        control,
        deadline,
        repo_root,
        &["ls-tree", "-r", "-l", "-z", "--full-tree", source_commit],
        "git inspect bound patch tree",
    )?;
    ensure_git_success(&listing, "inspect bound patch tree")?;
    let (entries, batch_output_bound) = parse_tree_listing(
        &listing.stdout,
        limits,
        case_insensitive,
        source_commit.len(),
    )?;
    let tree_oid = resolve_tree_oid(repo_root, source_commit, control, deadline)?;
    let commit_body = read_commit_body(repo_root, source_commit, control, deadline, limits)?;
    verify_commit_body(repo_root, source_commit, &commit_body, control, deadline)?;
    Ok(BoundTreeManifest {
        source_commit: source_commit.to_string(),
        tree_oid,
        commit_body,
        entries,
        batch_output_bound,
    })
}

fn validate_source_commit(source_commit: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(source_commit.len(), 40 | 64)
            && source_commit.chars().all(|ch| ch.is_ascii_hexdigit()),
        "patch:finding bound source commit is not a full object id"
    );
    Ok(())
}

fn resolve_tree_oid(
    repo_root: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<String> {
    let spec = format!("{source_commit}^{{tree}}");
    let output = run_git_until(
        control,
        deadline,
        repo_root,
        &["rev-parse", "--verify", &spec],
        "git resolve bound patch tree",
    )?;
    ensure_git_success(&output, "resolve bound patch tree")?;
    read_single_oid(&output.stdout, source_commit.len(), "bound tree")
}

fn read_commit_body(
    repo_root: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
    deadline: Instant,
    limits: MaterializationLimits,
) -> Result<Vec<u8>> {
    let output = run_git_until(
        control,
        deadline,
        repo_root,
        &["cat-file", "commit", source_commit],
        "git read bound patch commit",
    )?;
    ensure_git_success(&output, "read bound patch commit")?;
    anyhow::ensure!(
        !output.stdout.is_empty() && output.stdout.len() <= limits.max_commit_bytes,
        "patch:finding bound commit object exceeds its byte limit"
    );
    Ok(output.stdout)
}

fn verify_commit_body(
    repo_root: &Path,
    source_commit: &str,
    commit_body: &[u8],
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let output = run_git_input_until(
        control,
        deadline,
        repo_root,
        &["hash-object", "-t", "commit", "--stdin"],
        commit_body,
        "git verify bound patch commit",
    )?;
    ensure_git_success(&output, "verify bound patch commit")?;
    let actual = read_single_oid(&output.stdout, source_commit.len(), "bound commit")?;
    anyhow::ensure!(
        actual == source_commit,
        "patch:finding bound commit bytes did not match the authorized object id"
    );
    Ok(())
}

fn read_single_oid(bytes: &[u8], expected_len: usize, label: &str) -> Result<String> {
    let oid = std::str::from_utf8(bytes)
        .with_context(|| format!("patch:finding {label} id was not UTF-8"))?
        .trim();
    anyhow::ensure!(
        oid.len() == expected_len && oid.chars().all(|ch| ch.is_ascii_hexdigit()),
        "patch:finding {label} id was invalid"
    );
    Ok(oid.to_ascii_lowercase())
}
