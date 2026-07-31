use super::*;
use crate::bounded_file::read_source_text_prefix;

const MAX_TAINT_SOURCE_FILES: usize = 20_000;
const MAX_TAINT_WALK_ENTRIES: usize = 100_000;
const MAX_TAINT_SOURCE_BYTES: usize = 512 * 1024 * 1024;

struct SourceWalkState {
    source_cap: usize,
    entry_cap: usize,
    entries_seen: usize,
    source_truncated: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextSourceFile {
    pub(crate) relative_path: String,
    pub(crate) language: String,
    pub(crate) lines: Vec<String>,
}

pub(crate) fn collect_taint_iris_next_source_files(
    root: &Path,
    max_files: Option<usize>,
    max_bytes_per_file: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    collect_taint_iris_next_source_files_with_limits(
        root,
        max_files,
        max_bytes_per_file,
        MAX_TAINT_SOURCE_FILES,
        MAX_TAINT_WALK_ENTRIES,
        MAX_TAINT_SOURCE_BYTES,
    )
}

fn collect_taint_iris_next_source_files_with_limits(
    root: &Path,
    max_files: Option<usize>,
    max_bytes_per_file: usize,
    source_cap: usize,
    entry_cap: usize,
    total_byte_cap: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    let paths =
        collect_taint_iris_next_source_paths_with_limits(root, max_files, source_cap, entry_cap)?;
    read_taint_source_paths(&paths, None, max_bytes_per_file, total_byte_cap)
}

pub(crate) fn collect_taint_iris_next_source_paths(
    root: &Path,
    max_files: Option<usize>,
) -> Result<Vec<TaintIrisNextSourcePath>> {
    collect_taint_iris_next_source_paths_with_limits(
        root,
        max_files,
        MAX_TAINT_SOURCE_FILES,
        MAX_TAINT_WALK_ENTRIES,
    )
}

fn collect_taint_iris_next_source_paths_with_limits(
    root: &Path,
    max_files: Option<usize>,
    source_cap: usize,
    entry_cap: usize,
) -> Result<Vec<TaintIrisNextSourcePath>> {
    let mut paths = Vec::new();
    let mut state = SourceWalkState {
        source_cap: max_files.unwrap_or(source_cap),
        entry_cap,
        entries_seen: 0,
        source_truncated: false,
    };
    collect_taint_iris_next_source_paths_inner(root, root, &mut state, &mut paths)?;
    anyhow::ensure!(
        max_files.is_some() || !state.source_truncated,
        "Taint source inventory exceeded the {}-file coverage limit",
        state.source_cap
    );
    Ok(paths)
}

fn collect_taint_iris_next_source_paths_inner(
    root: &Path,
    dir: &Path,
    state: &mut SourceWalkState,
    paths: &mut Vec<TaintIrisNextSourcePath>,
) -> Result<()> {
    if state.source_truncated {
        return Ok(());
    }
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("Could not read taint source directory {}", dir.display()))?;
    let remaining = state.entry_cap.saturating_sub(state.entries_seen);
    let mut entries = read_dir
        .take(remaining.saturating_add(1))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        entries.len() <= remaining,
        "Taint source inventory exceeded the {}-entry walk limit",
        state.entry_cap
    );
    state.entries_seen += entries.len();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if state.source_truncated {
            break;
        }
        collect_source_path_entry(root, entry, state, paths)?;
    }
    Ok(())
}

fn collect_source_path_entry(
    root: &Path,
    entry: fs::DirEntry,
    state: &mut SourceWalkState,
    paths: &mut Vec<TaintIrisNextSourcePath>,
) -> Result<()> {
    let path = entry.path();
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
        return collect_taint_iris_next_source_paths_inner(root, &path, state, paths);
    }
    if collectable_source_file(&file_type, &path) {
        record_source_path(root, path, state, paths);
    }
    Ok(())
}

fn record_source_path(
    root: &Path,
    path: PathBuf,
    state: &mut SourceWalkState,
    paths: &mut Vec<TaintIrisNextSourcePath>,
) {
    if paths.len() >= state.source_cap {
        state.source_truncated = true;
        return;
    }
    paths.push(source_path_record(root, path));
}

fn collectable_source_file(file_type: &fs::FileType, path: &Path) -> bool {
    file_type.is_file() && is_agentic_context_file(path)
}

fn source_path_record(root: &Path, path: PathBuf) -> TaintIrisNextSourcePath {
    let relative_path = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .display()
        .to_string();
    let language = language_for_path(&path);
    TaintIrisNextSourcePath {
        absolute_path: path,
        relative_path,
        language,
    }
}

fn read_taint_iris_next_source_file(
    path: &TaintIrisNextSourcePath,
    max_bytes_per_file: usize,
) -> Result<Option<TaintIrisNextSourceFile>> {
    let Some(text) = read_source_text_prefix(&path.absolute_path, max_bytes_per_file)
        .with_context(|| format!("Could not read taint source {}", path.relative_path))?
    else {
        return Ok(None);
    };
    Ok(Some(TaintIrisNextSourceFile {
        relative_path: path.relative_path.clone(),
        language: path.language.clone(),
        lines: text.lines().map(ToString::to_string).collect(),
    }))
}

fn read_taint_source_paths(
    paths: &[TaintIrisNextSourcePath],
    max_files: Option<usize>,
    max_bytes_per_file: usize,
    total_byte_cap: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    let path_count = max_files.unwrap_or(paths.len()).min(paths.len());
    let mut files = Vec::with_capacity(path_count);
    let mut total_bytes = 0usize;
    for path in paths.iter().take(path_count) {
        let Some(file) = read_taint_iris_next_source_file(path, max_bytes_per_file)? else {
            continue;
        };
        let bytes = file
            .lines
            .iter()
            .map(|line| line.len().saturating_add(1))
            .sum::<usize>();
        total_bytes = total_bytes.saturating_add(bytes);
        anyhow::ensure!(
            total_bytes <= total_byte_cap,
            "Taint source inventory exceeded the {total_byte_cap}-byte coverage limit"
        );
        files.push(file);
    }
    Ok(files)
}

pub(crate) fn read_taint_iris_next_source_paths(
    paths: &[TaintIrisNextSourcePath],
    max_files: Option<usize>,
    max_bytes_per_file: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    read_taint_source_paths(
        paths,
        max_files,
        max_bytes_per_file,
        MAX_TAINT_SOURCE_BYTES,
    )
}

pub(crate) fn detect_taint_iris_next_languages(root: &Path) -> Result<Vec<String>> {
    // Language detection only needs a representative sample; capping at 600
    // files keeps the language-fingerprinting cheap on huge repos and never
    // affects taint-hunt scope (which uses the complete, hard-bounded walker below).
    Ok(collect_taint_iris_next_source_files(root, Some(600), 1024)?
        .into_iter()
        .map(|file| file.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub(crate) fn detect_taint_iris_next_languages_in_paths(
    paths: &[TaintIrisNextSourcePath],
) -> Result<Vec<String>> {
    Ok(read_taint_iris_next_source_paths(paths, Some(600), 1024)?
        .into_iter()
        .map(|file| file.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub(crate) fn language_for_path(path: &Path) -> String {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    language_name_for_extension(extension).to_string()
}

fn language_name_for_extension(extension: &str) -> &'static str {
    language_kind_table()
        .iter()
        .find(|(extensions, _)| extensions.contains(&extension))
        .map(|(_, language)| *language)
        .unwrap_or("unknown")
}

fn language_kind_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["js", "jsx"], "javascript"),
        (&["ts", "tsx"], "typescript"),
        (&["py"], "python"),
        (&["rb"], "ruby"),
        (&["php"], "php"),
        (&["java"], "java"),
        (&["go"], "go"),
        (&["rs"], "rust"),
        (&["scala", "sc"], "scala"),
        // Known limitation: `.h` is treated as C. `.h` is genuinely ambiguous
        // (C and C++ both use it), and forcing it to `cpp` would misparse real
        // C headers, so C++ headers that use the `.h` extension narrow under
        // the C grammar — a bounded precision gap, not a correctness gate.
        (&["c", "h"], "c"),
        (&["cc", "cpp", "cxx", "hpp", "hh"], "cpp"),
        (&["cs"], "csharp"),
    ]
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
    )
}

#[cfg(test)]
mod coverage_limit_tests {
    use super::*;

    #[test]
    fn full_scope_walk_errors_instead_of_silently_truncating() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();

        let error =
            collect_taint_iris_next_source_files_with_limits(temp.path(), None, 1024, 1, 10, 1024)
                .unwrap_err();

        assert!(error.to_string().contains("file coverage limit"));
    }

    #[test]
    fn full_scope_walk_enforces_aggregate_source_bytes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("large.rs"), "x".repeat(64)).unwrap();

        let error =
            collect_taint_iris_next_source_files_with_limits(temp.path(), None, 1024, 10, 10, 8)
                .unwrap_err();

        assert!(error.to_string().contains("byte coverage limit"));
    }

    #[test]
    fn downstream_reads_reuse_the_collected_source_inventory() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("first.rs"), "fn first() {}\n").unwrap();
        let paths = collect_taint_iris_next_source_paths(temp.path(), None).unwrap();
        fs::write(temp.path().join("later.rs"), "fn later() {}\n").unwrap();

        let files = read_taint_iris_next_source_paths(&paths, None, 1024).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative_path, "first.rs");
    }
}
