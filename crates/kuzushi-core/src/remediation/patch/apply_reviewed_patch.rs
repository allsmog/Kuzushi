use super::*;
use std::path::Component;

const MAX_PATCH_TOUCHED_FILE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedPatchApplyReport {
    pub checked: bool,
    pub applied: bool,
    pub touched_paths: Vec<String>,
    pub touched_files: Vec<crate::findings::PatchLifecycleFile>,
    pub diff_hash: String,
    pub base_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedPatchApplyPlan {
    pub touched_paths: Vec<String>,
    pub touched_files: Vec<crate::findings::PatchLifecycleFile>,
    pub diff_hash: String,
    pub source_commit: String,
}

pub fn apply_reviewed_patch(repo_root: &Path, diff: &str) -> Result<ReviewedPatchApplyReport> {
    let control = unattended_patch_control();
    ensure_git_repository(repo_root, control)?;
    let source_commit = resolve_head_commit(repo_root, control)?;
    let plan = prepare_reviewed_patch_apply(repo_root, diff, &source_commit)?;
    apply_prepared_reviewed_patch(repo_root, diff, &plan)
}

pub fn prepare_reviewed_patch_apply(
    repo_root: &Path,
    diff: &str,
    source_commit: &str,
) -> Result<ReviewedPatchApplyPlan> {
    let control = unattended_patch_control();
    verify_patch_source_snapshot(repo_root, source_commit, control)?;
    let touched_paths = validated_diff_paths(diff)?;
    let before_hashes = touched_path_hashes(repo_root, &touched_paths)?;
    check_reviewed_patch(repo_root, diff, control)?;
    Ok(ReviewedPatchApplyPlan {
        touched_files: lifecycle_files(
            &touched_paths,
            &before_hashes,
            &vec![None; touched_paths.len()],
        ),
        touched_paths,
        diff_hash: patch_diff_hash(diff),
        source_commit: source_commit.to_string(),
    })
}

pub fn apply_prepared_reviewed_patch(
    repo_root: &Path,
    diff: &str,
    plan: &ReviewedPatchApplyPlan,
) -> Result<ReviewedPatchApplyReport> {
    anyhow::ensure!(
        patch_diff_hash(diff) == plan.diff_hash,
        "reviewed patch changed after application intent was recorded"
    );
    let control = unattended_patch_control();
    verify_patch_source_snapshot(repo_root, &plan.source_commit, control)?;
    ensure_planned_files_unchanged(repo_root, plan)?;
    check_reviewed_patch(repo_root, diff, control)?;
    run_git_with_input(repo_root, &["apply"], diff, control)
        .map_err(|error| anyhow::anyhow!("reviewed patch failed during `git apply`: {error:#}"))?;
    let after_hashes = touched_path_hashes(repo_root, &plan.touched_paths)?;
    Ok(ReviewedPatchApplyReport {
        checked: true,
        applied: true,
        touched_paths: plan.touched_paths.clone(),
        touched_files: lifecycle_files(
            &plan.touched_paths,
            &plan
                .touched_files
                .iter()
                .map(|file| file.before_hash.clone())
                .collect::<Vec<_>>(),
            &after_hashes,
        ),
        diff_hash: plan.diff_hash.clone(),
        base_commit: Some(plan.source_commit.clone()),
    })
}

fn check_reviewed_patch(
    repo_root: &Path,
    diff: &str,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    run_git_with_input(repo_root, &["apply", "--check"], diff, control)
        .map(|_| ())
        .map_err(|error| {
            anyhow::anyhow!("reviewed patch did not pass `git apply --check`: {error:#}")
        })
}

fn ensure_planned_files_unchanged(repo_root: &Path, plan: &ReviewedPatchApplyPlan) -> Result<()> {
    let current = touched_path_hashes(repo_root, &plan.touched_paths)?;
    let expected = plan
        .touched_files
        .iter()
        .map(|file| file.before_hash.clone())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        current == expected,
        "reviewed patch target files changed after application intent was recorded"
    );
    Ok(())
}

fn lifecycle_files(
    paths: &[String],
    before_hashes: &[Option<String>],
    after_hashes: &[Option<String>],
) -> Vec<crate::findings::PatchLifecycleFile> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| crate::findings::PatchLifecycleFile {
            path: path.clone(),
            before_hash: before_hashes[index].clone(),
            after_hash: after_hashes[index].clone(),
        })
        .collect()
}

pub(crate) fn patch_diff_hash(diff: &str) -> String {
    crate::identity::hash_parts("kuzushi.patch.diff.v1", &[diff.as_bytes()]).to_string()
}

fn touched_path_hashes(repo_root: &Path, paths: &[String]) -> Result<Vec<Option<String>>> {
    paths
        .iter()
        .map(|path| hash_optional_file(repo_root, Path::new(path)))
        .collect()
}

pub(crate) fn hash_optional_file(root: &Path, path: &Path) -> Result<Option<String>> {
    match crate::bounded_file::read_regular_bytes_within(root, path, MAX_PATCH_TOUCHED_FILE_BYTES) {
        Ok(bytes) => Ok(Some(
            crate::identity::hash_parts("kuzushi.patch.file.v1", &[&bytes]).to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
    }
}

fn validated_diff_paths(diff: &str) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for raw in candidate_diff_paths(diff)? {
        let Some(path) = normalize_patch_path(&raw)? else {
            continue;
        };
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        anyhow::bail!("reviewed patch did not name any repository-relative file paths");
    }
    Ok(paths)
}

/// The names every header in the diff carries, hunk bodies skipped whole.
///
/// A hunk body has to be skipped rather than scanned, because a removed source
/// line can look exactly like a name header: removing the SQL comment
/// `-- "../legacy"` puts `--- "../legacy"` in the body, which is a
/// well-formed quoted name and is indistinguishable from a `---` header by its
/// prefix alone. Git tells the two apart by position, and so does this. The
/// boundary rule is [`super::recount_hunks::hunk_body_end`], the one `recount_hunks`
/// canonicalized the diff with, so the two readers agree on where a body ends.
fn candidate_diff_paths(diff: &str) -> Result<Vec<String>> {
    let lines = diff
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let mut names = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        index = match hunk_body_bounds(&lines, index) {
            Some(body_end) => body_end,
            None => take_line_names(&lines, index, &mut names)?,
        };
    }
    Ok(names)
}

/// The index past a hunk opening at `index`, or `None` when no hunk opens
/// there. Always past `index`, so the walk cannot stall on an empty body.
fn hunk_body_bounds(lines: &[&str], index: usize) -> Option<usize> {
    lines[index]
        .starts_with("@@")
        .then(|| super::recount_hunks::hunk_body_end(lines, index + 1))
}

fn take_line_names(lines: &[&str], index: usize, names: &mut Vec<String>) -> Result<usize> {
    names.extend(candidate_paths_from_line(lines[index])?);
    Ok(index + 1)
}

fn candidate_paths_from_line(line: &str) -> Result<Vec<String>> {
    if let Some(rest) = line.strip_prefix("diff --git ") {
        return diff_git_paths(rest);
    }
    Ok(header_name_body(line)
        .and_then(header_name)
        .map_or_else(Vec::new, |name| vec![name]))
}

/// The headers that carry exactly one name, which is the whole rest of the
/// line — so a name holding a space needs no disambiguation here.
fn header_name_body(line: &str) -> Option<&str> {
    [
        "--- ",
        "+++ ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
    ]
    .into_iter()
    .find_map(|prefix| line.strip_prefix(prefix))
}

/// One name from a single-name header. Git quotes the name when it needs
/// escaping; otherwise it appends a tab when the name itself holds whitespace,
/// so the tab is metadata and never part of the name.
///
/// `None` when the quoting is malformed. Git never writes a malformed quoted
/// name, so such a line is diff content that merely opens like a header — a
/// removed `-- "unclosed` reaches this reader as `--- "unclosed` — and content
/// names no path.
fn header_name(rest: &str) -> Option<String> {
    match crate::git_quoted_path::take_quoted_path(rest.trim_end()) {
        Ok(Some((name, _))) => Some(name),
        Ok(None) => Some(trim_diff_metadata(rest).to_string()),
        Err(_) => None,
    }
}

/// The two names a `diff --git` line carries.
///
/// An unquoted line is ambiguous whenever a name holds a space — `diff --git
/// a/my file.txt b/my file.txt` splits on whitespace into four tokens, and
/// reading the first two as the names invents `my` and `file.txt`. The split
/// is resolved the way git resolves it: find the space where the `a/` and `b/`
/// sides name the same path. A rename or copy whose unquoted names differ
/// *and* hold spaces cannot be split at all, so this contributes none rather
/// than a guess, and the authoritative names come from the `rename`/`copy`
/// headers.
fn diff_git_paths(rest: &str) -> Result<Vec<String>> {
    if let Some(pair) = quoted_name_pair(rest)? {
        return Ok(pair);
    }
    Ok(shared_name_pair(rest).unwrap_or_else(|| space_free_name_pair(rest)))
}

/// Both names when git quoted a side, or `None` when neither is quoted.
///
/// Git quotes only the side that needs escaping — `diff --git
/// "a/caf\303\251.txt" b/plain.txt` is a real rename header — and a name that
/// would need a quote is always the quoted one. So an unquoted side holds no
/// quote character, and the first quote in the line opens the quoted side and
/// bounds the other.
fn quoted_name_pair(rest: &str) -> Result<Option<Vec<String>>> {
    let Some(quote) = rest.find('"') else {
        return Ok(None);
    };
    let Some((quoted, tail)) = bounded_quoted_side(rest, quote)? else {
        return Ok(None);
    };
    let (before, after) = (rest[..quote].trim_end(), tail.trim_start());
    if before.is_empty() {
        return Ok(Some(vec![quoted, side_name(after)?]));
    }
    Ok(after.is_empty().then_some(vec![before.to_string(), quoted]))
}

/// The quoted side the first quote opens. A quote past the start of the line
/// opens a side only when its quoting is well formed and bounded; otherwise it
/// is a character inside a name some writer left unquoted, and the unquoted
/// readings take the line. A line that *begins* with a quote is git's own
/// quoted form, so malformed quoting there is an error rather than a guess.
fn bounded_quoted_side(rest: &str, quote: usize) -> Result<Option<(String, &str)>> {
    let side = quoted_side(&rest[quote..]);
    match quote {
        0 => side,
        _ => Ok(side.unwrap_or_default()),
    }
}

/// The decoded name of a quoted side plus the text after it. `None` when the
/// quotes bound no side, because a closing quote that leaves text attached to
/// it closed nothing.
fn quoted_side(text: &str) -> Result<Option<(String, &str)>> {
    let Some((name, tail)) = crate::git_quoted_path::take_quoted_path(text)? else {
        return Ok(None);
    };
    let bounded = tail.is_empty() || tail.starts_with(' ');
    Ok(bounded.then_some((name, tail)))
}

/// One side as written: the quoted name it is, or the literal text it is.
fn side_name(text: &str) -> Result<String> {
    match quoted_side(text)? {
        Some((name, _)) => Ok(name),
        None => Ok(text.to_string()),
    }
}

/// The split of `a/<name> b/<name>` where both sides name the same path, which
/// is every diff header but a rename or a copy.
fn shared_name_pair(rest: &str) -> Option<Vec<String>> {
    rest.bytes()
        .enumerate()
        .filter(|(_, byte)| *byte == b' ')
        .find_map(|(index, _)| prefixed_name_pair(rest, index))
}

/// The sides of a candidate split, kept with their `a/`/`b/` prefixes so
/// [`normalize_patch_path`] strips exactly one — a repository that really has
/// an `a/` directory keeps its own path.
fn prefixed_name_pair(rest: &str, index: usize) -> Option<Vec<String>> {
    let (left, right) = (&rest[..index], &rest[index + 1..]);
    let same = left.strip_prefix("a/")? == right.strip_prefix("b/")?;
    same.then(|| vec![left.to_string(), right.to_string()])
}

/// The two names of a header holding no space at all. Anything else is a
/// header whose names this reader cannot bound, and inventing tokens from it
/// is what put paths that do not exist into the lifecycle record.
fn space_free_name_pair(rest: &str) -> Vec<String> {
    let names = rest.split(' ').collect::<Vec<_>>();
    match <[&str; 2]>::try_from(names.as_slice()) {
        Ok([left, right]) => vec![left.to_string(), right.to_string()],
        Err(_) => Vec::new(),
    }
}

fn trim_diff_metadata(value: &str) -> &str {
    value.split('\t').next().unwrap_or(value).trim()
}

fn normalize_patch_path(raw: &str) -> Result<Option<String>> {
    let raw = trim_diff_metadata(raw);
    if raw == "/dev/null" {
        return Ok(None);
    }
    let path = raw
        .strip_prefix("a/")
        .or_else(|| raw.strip_prefix("b/"))
        .unwrap_or(raw);
    validate_repository_relative_path(path)?;
    Ok(Some(path.to_string()))
}

fn validate_repository_relative_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        anyhow::bail!("reviewed patch contains an empty file path");
    }
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        anyhow::bail!("reviewed patch path {path:?} must be repository-relative");
    }
    for component in candidate.components() {
        validate_repository_path_component(component, path)?;
    }
    Ok(())
}

fn validate_repository_path_component(component: Component<'_>, path: &str) -> Result<()> {
    match component {
        Component::Normal(value) if value == std::ffi::OsStr::new(".git") => {
            anyhow::bail!("reviewed patch must not write inside .git");
        }
        Component::Normal(_) | Component::CurDir => Ok(()),
        Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
            anyhow::bail!("reviewed patch path {path:?} escapes the repository root");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn apply_reviewed_patch_updates_active_worktree() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);

        let report = apply_reviewed_patch(repo, demo_diff()).unwrap();

        assert!(report.checked);
        assert!(report.applied);
        assert_eq!(report.touched_paths, vec!["demo.txt"]);
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "after\n"
        );
    }

    #[test]
    fn reviewed_patch_rejects_path_traversal() {
        let error = validated_diff_paths(
            "diff --git a/../outside.txt b/../outside.txt\n\
             --- a/../outside.txt\n\
             +++ b/../outside.txt\n",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("escapes the repository root"));
    }

    #[test]
    fn reviewed_patch_rejects_git_dir_writes() {
        let error = validated_diff_paths(
            "diff --git a/.git/config b/.git/config\n\
             --- a/.git/config\n\
             +++ b/.git/config\n",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains(".git"));
    }

    #[test]
    fn a_name_holding_a_space_is_the_only_path_recorded() {
        let paths = validated_diff_paths(
            "diff --git a/my file.txt b/my file.txt\n\
             --- a/my file.txt\t\n\
             +++ b/my file.txt\t\n\
             @@ -1 +1 @@\n\
             -before\n\
             +after\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["my file.txt"]);
    }

    #[test]
    fn a_mode_only_header_still_names_its_file() {
        let paths = validated_diff_paths(
            "diff --git a/my file.txt b/my file.txt\n\
             old mode 100644\n\
             new mode 100755\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["my file.txt"]);
    }

    #[test]
    fn a_quoted_name_is_decoded_to_the_file_on_disk() {
        let paths = validated_diff_paths(
            "diff --git \"a/src/caf\\303\\251.rs\" \"b/src/caf\\303\\251.rs\"\n\
             --- \"a/src/caf\\303\\251.rs\"\n\
             +++ \"b/src/caf\\303\\251.rs\"\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["src/café.rs"]);
    }

    #[test]
    fn a_rename_quoting_only_one_side_reads_both_names() {
        let from_quoted = validated_diff_paths(
            "diff --git \"a/caf\\303\\251.txt\" b/plain.txt\n\
             similarity index 100%\n\
             rename from \"caf\\303\\251.txt\"\n\
             rename to plain.txt\n",
        )
        .unwrap();
        let to_quoted = validated_diff_paths(
            "diff --git a/plain.txt \"b/caf\\303\\251.txt\"\n\
             similarity index 100%\n\
             rename from plain.txt\n\
             rename to \"caf\\303\\251.txt\"\n",
        )
        .unwrap();

        assert_eq!(from_quoted, vec!["café.txt", "plain.txt"]);
        assert_eq!(to_quoted, vec!["plain.txt", "café.txt"]);
    }

    #[test]
    fn a_quote_inside_an_unquoted_name_is_part_of_the_name() {
        let paths = validated_diff_paths(
            "diff --git a/we\"ird.txt b/we\"ird.txt\n\
             --- a/we\"ird.txt\n\
             +++ b/we\"ird.txt\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["we\"ird.txt"]);
    }

    #[test]
    fn a_rename_holding_spaces_takes_its_names_from_the_rename_headers() {
        let paths = validated_diff_paths(
            "diff --git a/my file.txt b/your file.txt\n\
             similarity index 100%\n\
             rename from my file.txt\n\
             rename to your file.txt\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["my file.txt", "your file.txt"]);
    }

    #[test]
    fn a_repository_directory_named_a_keeps_its_own_path() {
        let paths = validated_diff_paths(
            "diff --git a/a/demo rs.txt b/a/demo rs.txt\n\
             --- a/a/demo rs.txt\t\n\
             +++ b/a/demo rs.txt\t\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["a/demo rs.txt"]);
    }

    #[test]
    fn the_path_guards_read_the_decoded_name_not_the_quoted_text() {
        let traversal = validated_diff_paths(
            "diff --git \"a/\\056\\056/outside.txt\" \"b/\\056\\056/outside.txt\"\n",
        )
        .unwrap_err()
        .to_string();
        let git_dir =
            validated_diff_paths("diff --git \"a/\\056git/config\" \"b/\\056git/config\"\n")
                .unwrap_err()
                .to_string();

        assert!(traversal.contains("escapes the repository root"), "{traversal}");
        assert!(git_dir.contains(".git"), "{git_dir}");
    }

    #[test]
    fn malformed_quoting_is_refused_rather_than_recorded_as_a_path() {
        let error = validated_diff_paths("diff --git \"a/unterminated.txt b/unterminated.txt\n")
            .unwrap_err()
            .to_string();

        assert!(error.contains("closing quote"), "{error}");
    }

    #[test]
    fn diff_content_that_opens_like_a_header_is_not_read_as_a_name() {
        let paths = validated_diff_paths(
            "diff --git a/query.sql b/query.sql\n\
             --- a/query.sql\n\
             +++ b/query.sql\n\
             @@ -1 +1 @@\n\
             --- \"unclosed legacy note\n\
             +-- closed note\n",
        )
        .unwrap();

        assert_eq!(paths, vec!["query.sql"]);
    }

    #[test]
    fn a_removed_comment_inside_a_hunk_is_not_read_as_a_name() {
        // Captured from `git diff` after removing the line `-- "../legacy"`.
        let paths = validated_diff_paths(&diff_text(&[
            "diff --git a/query.sql b/query.sql",
            "index af761b7..33791bf 100644",
            "--- a/query.sql",
            "+++ b/query.sql",
            "@@ -1,3 +1,2 @@",
            " SELECT 1;",
            "--- \"../legacy\"",
            " SELECT 2;",
        ]))
        .unwrap();

        assert_eq!(paths, vec!["query.sql"]);
    }

    #[test]
    fn a_file_section_after_a_hunk_is_still_read() {
        let paths = validated_diff_paths(&diff_text(&[
            "diff --git a/first.sql b/first.sql",
            "--- a/first.sql",
            "+++ b/first.sql",
            "@@ -1,2 +1,1 @@",
            " SELECT 1;",
            "--- \"../legacy\"",
            "diff --git a/second.sql b/second.sql",
            "--- a/second.sql",
            "+++ b/second.sql",
            "@@ -1 +1 @@",
            "-SELECT 2;",
            "+SELECT 3;",
        ]))
        .unwrap();

        assert_eq!(paths, vec!["first.sql", "second.sql"]);
    }

    #[test]
    fn apply_records_the_real_path_of_a_name_holding_a_space() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        run_git(repo, &["init"]);
        std::fs::write(repo.join("my file.txt"), "before\n").unwrap();
        run_git(repo, &["add", "my file.txt"]);
        run_git(repo, &["commit", "-m", "initial"]);

        let report = apply_reviewed_patch(repo, spaced_name_diff()).unwrap();

        assert_eq!(report.touched_paths, vec!["my file.txt"]);
        assert_eq!(
            report.touched_files[0].path.as_str(),
            "my file.txt",
            "lifecycle record must name the file that changed"
        );
        assert!(report.touched_files[0].before_hash.is_some());
        assert!(report.touched_files[0].after_hash.is_some());
        assert_eq!(
            std::fs::read_to_string(repo.join("my file.txt")).unwrap(),
            "after\n"
        );
    }

    #[test]
    fn preparation_is_source_bound_and_does_not_mutate() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let source = resolve_head_commit(repo, unattended_patch_control()).unwrap();

        let plan = prepare_reviewed_patch_apply(repo, demo_diff(), &source).unwrap();

        assert_eq!(plan.source_commit, source);
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "before\n"
        );
    }

    #[test]
    fn preparation_rejects_a_different_generation_commit() {
        if git_is_unavailable() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        initialize_repo(repo);
        let wrong_source = "0123456789012345678901234567890123456789";

        let error = prepare_reviewed_patch_apply(repo, demo_diff(), wrong_source)
            .unwrap_err()
            .to_string();

        assert!(error.contains("source commit changed"));
        assert_eq!(
            std::fs::read_to_string(repo.join("demo.txt")).unwrap(),
            "before\n"
        );
    }

    fn initialize_repo(repo: &Path) {
        run_git(repo, &["init"]);
        std::fs::write(repo.join("demo.txt"), "before\n").unwrap();
        run_git(repo, &["add", "demo.txt"]);
        run_git(repo, &["commit", "-m", "initial"]);
    }

    fn git_is_unavailable() -> bool {
        Command::new("git").arg("--version").output().is_err()
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.email=kuzushi@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(repo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    /// A diff written line by line. A `\\`-continued string literal drops the
    /// leading whitespace of each continued line, which would silently strip
    /// the leading space off a context line and change where the hunk ends.
    fn diff_text(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    fn spaced_name_diff() -> &'static str {
        "diff --git a/my file.txt b/my file.txt\n\
         --- a/my file.txt\t\n\
         +++ b/my file.txt\t\n\
         @@ -1 +1 @@\n\
         -before\n\
         +after\n"
    }

    fn demo_diff() -> &'static str {
        "diff --git a/demo.txt b/demo.txt\n\
         --- a/demo.txt\n\
         +++ b/demo.txt\n\
         @@ -1 +1 @@\n\
         -before\n\
         +after\n"
    }
}
