use super::*;

const MAX_REFRESH_RUNS: usize = 8;
const MAX_REFRESH_VISITED_ENTRIES: usize = 512;
const MAX_REFRESH_SOURCES: usize = 128;
const MAX_REFRESH_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REFRESH_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REFRESH_DEPTH: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArtifactCandidateBatch {
    pub paths: Vec<String>,
    pub partial: bool,
}

pub(crate) fn refresh_artifact_record_candidates(
    workspace: &WorkspaceTarget,
) -> Result<ArtifactCandidateBatch> {
    let mut collector = RefreshCandidateCollector::default();
    for source_path in fixed_artifact_paths(workspace.root()) {
        collector.add_known_source(workspace.root(), &source_path)?;
    }
    let (run_dirs, partial) = recent_run_directories(workspace)?;
    collector.partial |= partial;
    for run_dir in run_dirs {
        if !collect_refresh_run_dir(workspace.root(), &run_dir, 0, &mut collector)? {
            break;
        }
    }
    collector.paths.sort();
    collector.paths.dedup();
    Ok(ArtifactCandidateBatch {
        paths: collector.paths,
        partial: collector.partial,
    })
}

pub(crate) fn artifact_record_candidates(workspace: &WorkspaceTarget) -> Result<Vec<String>> {
    let mut candidates = fixed_artifact_paths(workspace.root());
    let runs = crate::run_artifacts::checked_runs_root(workspace.root())?;
    collect_run_artifact_paths(workspace.root(), &runs, &mut candidates)?;
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn fixed_artifact_paths(root: &Path) -> Vec<String> {
    let mut candidates = persistent_workspace_artifact_paths(root);
    candidates.extend([
        ".kuzushi/tm-artifacts/normalized-threat-model.json".to_string(),
        "x-ray/x-ray.md".to_string(),
        "x-ray/entry-points.md".to_string(),
        "x-ray/invariants.md".to_string(),
        "x-ray/architecture.svg".to_string(),
    ]);
    candidates
}

fn persistent_workspace_artifact_paths(root: &Path) -> Vec<String> {
    [
        crate::context::context_snapshot_path(root),
        crate::capabilities::persistent_threat_model_path(root),
    ]
    .into_iter()
    .map(|path| relative_workspace_path(root, &path))
    .collect()
}

pub(crate) fn workspace_artifact_record(
    workspace: &WorkspaceTarget,
    source_path: String,
) -> Result<Option<ArtifactKnowledgeRecord>> {
    if explicit_context_run_source(workspace.root(), &source_path)? {
        return Ok(None);
    }
    let absolute = crate::workspace::validated_workspace_descendant(
        workspace.root(),
        Path::new(&source_path),
    )?;
    if !is_indexable_artifact(&absolute)? {
        return Ok(None);
    }
    let body = crate::bounded_file::read_utf8_text_within(
        workspace.root(),
        &absolute,
        MAX_REFRESH_SOURCE_BYTES as usize,
    )
    .with_context(|| format!("Could not read artifact {}", absolute.display()))?;
    let body = artifact_body_without_lessons(workspace.root(), &absolute, body)?;
    if unselected_lesson_artifact(&body) {
        return Ok(None);
    }
    Ok(Some(artifact_record_from_body(
        workspace,
        source_path,
        &absolute,
        body,
    )))
}

fn unselected_lesson_artifact(body: &str) -> bool {
    [
        "reviewedLessons",
        "Operator-reviewed lessons for this context",
        "\"lessonRef\"",
        "\"kuzushiLessons\"",
    ]
    .iter()
    .any(|marker| body.contains(marker))
}

fn artifact_body_without_lessons(root: &Path, absolute: &Path, body: String) -> Result<String> {
    if absolute == crate::capabilities::persistent_threat_model_path(root) {
        return without_reviewed_lessons(body);
    }
    Ok(body)
}

fn is_indexable_artifact(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && is_indexable_text_path(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("Could not inspect artifact {}", path.display()))
        }
    }
}

fn artifact_record_from_body(
    workspace: &WorkspaceTarget,
    source_path: String,
    absolute: &Path,
    body: String,
) -> ArtifactKnowledgeRecord {
    let metadata = json!({
        "sourceKind": if is_run_artifact_source_path(workspace.root(), &source_path) { "run-artifact" } else { "artifact-file" },
        "relativePath": source_path,
    });
    let module_id = infer_module_id(&source_path, &body);
    let run_id = infer_run_id(&source_path);
    let title = infer_title(&source_path, absolute);
    ArtifactKnowledgeRecord::from_body(
        source_path,
        module_id,
        run_id,
        title,
        body,
        Vec::new(),
        metadata,
    )
}

#[derive(Default)]
struct RefreshCandidateCollector {
    paths: Vec<String>,
    visited_entries: usize,
    total_bytes: u64,
    partial: bool,
}

impl RefreshCandidateCollector {
    fn add_known_source(&mut self, root: &Path, source_path: &str) -> Result<()> {
        let absolute =
            crate::workspace::validated_workspace_descendant(root, Path::new(source_path))?;
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).with_context(|| inspect_error(&absolute)),
        };
        if metadata.file_type().is_symlink() {
            self.partial = true;
            return Ok(());
        }
        self.add_file(root, &absolute, &metadata);
        Ok(())
    }

    fn add_file(&mut self, root: &Path, path: &Path, metadata: &fs::Metadata) {
        if !metadata.is_file() || !is_indexable_text_path(path) {
            return;
        }
        if !self.has_capacity_for(metadata.len()) {
            self.partial = true;
            return;
        }
        self.total_bytes += metadata.len();
        self.paths.push(relative_workspace_path(root, path));
    }

    fn has_capacity_for(&self, bytes: u64) -> bool {
        bytes <= MAX_REFRESH_SOURCE_BYTES
            && self.paths.len() < MAX_REFRESH_SOURCES
            && self.total_bytes.saturating_add(bytes) <= MAX_REFRESH_TOTAL_BYTES
    }

    fn reserve_entry(&mut self) -> bool {
        if self.visited_entries >= MAX_REFRESH_VISITED_ENTRIES {
            self.partial = true;
            return false;
        }
        self.visited_entries += 1;
        true
    }
}

fn recent_run_directories(workspace: &WorkspaceTarget) -> Result<(Vec<PathBuf>, bool)> {
    let limit = MAX_REFRESH_RUNS + 1;
    match crate::run_artifacts::list_current_run_summary_prefix(workspace.root(), limit) {
        Ok(Some(prefix)) => Ok(select_recent_run_directories(prefix)),
        Ok(None) | Err(_) => fallback_latest_run_directory(workspace),
    }
}

fn select_recent_run_directories(
    prefix: crate::run_artifacts::CurrentRunSummaryPrefix,
) -> (Vec<PathBuf>, bool) {
    let partial = prefix.canonical_total as usize > MAX_REFRESH_RUNS;
    let mut had_issue = false;
    let directories = prefix
        .entries
        .into_iter()
        .take(MAX_REFRESH_RUNS)
        .filter_map(|entry| match entry.state {
            crate::run_artifacts::RunSummaryEntryState::Ready(_) => Some(entry.path),
            crate::run_artifacts::RunSummaryEntryState::Issue(_) => {
                had_issue = true;
                None
            }
        })
        .collect();
    (directories, partial || had_issue)
}

fn fallback_latest_run_directory(workspace: &WorkspaceTarget) -> Result<(Vec<PathBuf>, bool)> {
    let state = crate::run_artifacts::read_latest_run_pointer(workspace.root())?;
    match state {
        crate::run_artifacts::LatestRunPointerState::Ready(run_id) => Ok((
            vec![crate::run_artifacts::run_dir(
                workspace.root(),
                run_id.as_str(),
            )],
            true,
        )),
        crate::run_artifacts::LatestRunPointerState::Missing => Ok((Vec::new(), false)),
        crate::run_artifacts::LatestRunPointerState::Invalid(_) => Ok((Vec::new(), true)),
    }
}

fn collect_refresh_run_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    collector: &mut RefreshCandidateCollector,
) -> Result<bool> {
    if explicit_context_run(root, dir)? {
        return Ok(true);
    }
    if !refresh_directory_is_traversable(dir, depth, collector)? {
        return Ok(true);
    }
    collect_refresh_run_entries(root, dir, depth, collector)
}

fn collect_refresh_run_entries(
    root: &Path,
    dir: &Path,
    depth: usize,
    collector: &mut RefreshCandidateCollector,
) -> Result<bool> {
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        if !collector.reserve_entry() {
            return Ok(false);
        }
        if !collect_refresh_run_entry(root, entry?, depth, collector)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn refresh_directory_is_traversable(
    dir: &Path,
    depth: usize,
    collector: &mut RefreshCandidateCollector,
) -> Result<bool> {
    if depth > MAX_REFRESH_DEPTH {
        collector.partial = true;
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(dir).with_context(|| inspect_error(dir))?;
    let traversable = metadata.is_dir() && !metadata.file_type().is_symlink();
    collector.partial |= !traversable;
    Ok(traversable)
}

fn collect_refresh_run_entry(
    root: &Path,
    entry: fs::DirEntry,
    depth: usize,
    collector: &mut RefreshCandidateCollector,
) -> Result<bool> {
    let kind = entry.file_type()?;
    if kind.is_symlink() {
        return Ok(true);
    }
    let path = entry.path();
    if kind.is_dir() {
        return collect_refresh_run_dir(root, &path, depth + 1, collector);
    }
    if kind.is_file() {
        collector.add_file(root, &path, &entry.metadata()?);
    }
    Ok(!collector.partial || collector.paths.len() < MAX_REFRESH_SOURCES)
}

fn inspect_error(path: &Path) -> String {
    format!("Could not inspect artifact path {}", path.display())
}

pub(crate) fn collect_run_artifact_paths(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
) -> Result<()> {
    if explicit_context_run(root, dir)? {
        return Ok(());
    }
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Artifact directory must not be a symlink: {}",
                dir.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => anyhow::bail!("Artifact path is not a directory: {}", dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", dir.display()))
        }
    }
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        collect_run_artifact_entry(root, entry?, out)?;
    }
    Ok(())
}

fn explicit_context_run_source(root: &Path, source_path: &str) -> Result<bool> {
    let runs = crate::run_artifacts::runs_root(root);
    let relative = runs
        .strip_prefix(root)
        .context("Runs are outside workspace")?;
    let Ok(path) = Path::new(source_path).strip_prefix(relative) else {
        return Ok(false);
    };
    let mut components = path.components();
    let Some(run) = components.next() else {
        return Ok(false);
    };
    explicit_context_run(root, &runs.join(run.as_os_str()))
}

fn without_reviewed_lessons(body: String) -> Result<String> {
    let Ok(mut document) = serde_json::from_str::<Value>(&body) else {
        return Ok(body);
    };
    let Some(object) = document.as_object_mut() else {
        return Ok(body);
    };
    if object.remove("reviewedLessons").is_none() {
        return Ok(body);
    }
    object.remove("lessonSelection");
    Ok(serde_json::to_string(&document)?)
}

fn explicit_context_run(root: &Path, dir: &Path) -> Result<bool> {
    let metadata = dir.join("run.json");
    if !metadata.exists() {
        return Ok(false);
    }
    let raw = crate::bounded_file::read_utf8_text_within(root, &metadata, 262144)?;
    let value: Value = serde_json::from_str(&raw).context("Artifact run metadata is malformed")?;
    let tool = value
        .get("tool")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(tool.starts_with("findings:lesson") || tool == "threat-model:reuse-lessons")
}

fn collect_run_artifact_entry(
    root: &Path,
    entry: fs::DirEntry,
    out: &mut Vec<String>,
) -> Result<()> {
    let kind = entry.file_type()?;
    if kind.is_symlink() {
        return Ok(());
    }
    let path = entry.path();
    if kind.is_dir() {
        return collect_run_artifact_paths(root, &path, out);
    }
    if kind.is_file() {
        append_indexable_run_artifact(root, &path, out);
    }
    Ok(())
}

fn append_indexable_run_artifact(root: &Path, path: &Path, out: &mut Vec<String>) {
    if is_indexable_text_path(path) {
        out.push(relative_workspace_path(root, path));
    }
}

pub(crate) fn is_indexable_text_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("json" | "jsonl" | "md" | "txt" | "svg" | "sarif")
    )
}

pub(crate) fn infer_module_id(source_path: &str, body: &str) -> String {
    if let Some(module_id) = infer_static_artifact_module_id(source_path) {
        return module_id;
    }
    if source_path.ends_with("run.json") {
        return infer_summary_artifact_module_id(body);
    }
    "artifact".to_string()
}

fn infer_static_artifact_module_id(source_path: &str) -> Option<String> {
    if source_path == context_snapshot_record_source_path() {
        return Some("context".to_string());
    }
    if source_path.starts_with("x-ray/") {
        return Some("x-ray".to_string());
    }
    if source_path.contains("threat-model")
        || source_path.contains("randori")
        || source_path.contains("pasta-")
    {
        return Some("threat-model".to_string());
    }
    None
}

fn infer_summary_artifact_module_id(body: &str) -> String {
    if body.contains("carliniThreatHunt") || body.contains("carlini-threat-hunt") {
        return "carlini-threat-hunt".to_string();
    }
    if body.contains("xRay") || body.contains("x-ray") {
        return "x-ray".to_string();
    }
    "sast".to_string()
}

fn context_snapshot_record_source_path() -> String {
    let root = Path::new("");
    relative_workspace_path(root, &crate::context::context_snapshot_path(root))
}

pub(crate) fn infer_run_id(source_path: &str) -> Option<String> {
    source_path
        .strip_prefix(&run_artifact_source_prefix(Path::new("")))
        .and_then(|suffix| suffix.split('/').next())
        .filter(|run_id| !run_id.is_empty())
        .map(ToString::to_string)
}

fn is_run_artifact_source_path(root: &Path, source_path: &str) -> bool {
    source_path.starts_with(&run_artifact_source_prefix(root))
}

fn run_artifact_source_prefix(root: &Path) -> String {
    format!("{}/", relative_workspace_path(root, &runs_root(root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_source_limit_is_exact_and_plus_one_is_partial() {
        let exact = tempfile::tempdir().unwrap();
        write_refresh_sources(exact.path(), MAX_REFRESH_SOURCES);
        let mut collector = RefreshCandidateCollector::default();
        collect_refresh_run_dir(exact.path(), exact.path(), 0, &mut collector).unwrap();
        assert_eq!(collector.paths.len(), MAX_REFRESH_SOURCES);
        assert!(!collector.partial);

        let overflow = tempfile::tempdir().unwrap();
        write_refresh_sources(overflow.path(), MAX_REFRESH_SOURCES + 1);
        let mut collector = RefreshCandidateCollector::default();
        collect_refresh_run_dir(overflow.path(), overflow.path(), 0, &mut collector).unwrap();
        assert_eq!(collector.paths.len(), MAX_REFRESH_SOURCES);
        assert!(collector.partial);
    }

    #[test]
    fn recent_run_limit_preserves_newest_first_prefix_and_reports_overflow() {
        let exact = recent_prefix(MAX_REFRESH_RUNS);
        let (directories, partial) = select_recent_run_directories(exact);
        assert_eq!(directories.len(), MAX_REFRESH_RUNS);
        assert_eq!(directories[0], PathBuf::from("run-000"));
        assert!(!partial);

        let overflow = recent_prefix(MAX_REFRESH_RUNS + 1);
        let (directories, partial) = select_recent_run_directories(overflow);
        assert_eq!(directories.len(), MAX_REFRESH_RUNS);
        assert_eq!(directories[0], PathBuf::from("run-000"));
        assert!(partial);
    }

    fn recent_prefix(count: usize) -> crate::run_artifacts::CurrentRunSummaryPrefix {
        let entries = (0..count)
            .map(|index| crate::run_artifacts::RunSummaryEntry {
                run_id: format!("run-{index:03}"),
                path: PathBuf::from(format!("run-{index:03}")),
                state: crate::run_artifacts::RunSummaryEntryState::Ready(
                    crate::run_artifacts::RunSummary::running(
                        format!("run-{index:03}"),
                        "tool",
                        None,
                        "target",
                    ),
                ),
            })
            .collect();
        crate::run_artifacts::CurrentRunSummaryPrefix {
            entries,
            canonical_total: count as u64,
        }
    }

    fn write_refresh_sources(root: &Path, count: usize) {
        for index in 0..count {
            fs::write(root.join(format!("artifact-{index:03}.json")), "{}").unwrap();
        }
    }

    #[test]
    fn persistent_workspace_artifact_paths_use_shared_helpers() {
        let root = Path::new("/repo");

        assert_eq!(
            persistent_workspace_artifact_paths(root),
            vec![
                relative_workspace_path(root, &crate::context::context_snapshot_path(root)),
                relative_workspace_path(
                    root,
                    &crate::capabilities::persistent_threat_model_path(root)
                ),
            ]
        );
    }

    #[test]
    fn context_snapshot_record_source_path_uses_context_helper() {
        assert_eq!(
            context_snapshot_record_source_path(),
            relative_workspace_path(
                Path::new(""),
                &crate::context::context_snapshot_path(Path::new(""))
            )
        );
    }

    #[test]
    fn run_artifact_source_prefix_uses_runs_root() {
        let root = Path::new("/repo");
        let source_path = relative_workspace_path(
            root,
            &crate::run_artifacts::run_dir(root, "run-1").join("report.md"),
        );

        assert_eq!(
            run_artifact_source_prefix(root),
            format!("{}/", relative_workspace_path(root, &runs_root(root)))
        );
        assert!(is_run_artifact_source_path(root, &source_path));
        assert_eq!(infer_run_id(&source_path), Some("run-1".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_discovery_rejects_symlinked_runs_root() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".kuzushi/v3")).unwrap();
        fs::write(outside.path().join("report.md"), "secret").unwrap();
        symlink(outside.path(), target.path().join(".kuzushi/v3/runs")).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let error = artifact_record_candidates(&workspace).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(
            fs::read_to_string(outside.path().join("report.md")).unwrap(),
            "secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_artifact_discovery_skips_nested_symlink_directories() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run = target.path().join(".kuzushi/v3/runs/run-safe");
        fs::create_dir_all(&run).unwrap();
        fs::write(outside.path().join("report.md"), "secret").unwrap();
        symlink(outside.path(), run.join("linked")).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let candidates = artifact_record_candidates(&workspace).unwrap();

        assert!(!candidates.iter().any(|path| path.contains("linked")));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_record_rejects_symlinked_persistent_artifact() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = target.path().join("outside.md");
        let linked = target.path().join("x-ray/x-ray.md");
        fs::write(&outside, "secret").unwrap();
        fs::create_dir_all(linked.parent().unwrap()).unwrap();
        symlink(&outside, &linked).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let error =
            workspace_artifact_record(&workspace, "x-ray/x-ray.md".to_string()).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(fs::read_to_string(outside).unwrap(), "secret");
    }
}
