use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextSourceFile {
    pub(crate) relative_path: String,
    pub(crate) language: String,
    pub(crate) lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextSourcePath {
    pub(crate) absolute_path: PathBuf,
    pub(crate) relative_path: String,
    pub(crate) language: String,
}

pub(crate) fn collect_taint_iris_next_source_files(
    root: &Path,
    max_files: Option<usize>,
    max_bytes_per_file: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    Ok(collect_taint_iris_next_source_paths(root, max_files)?
        .into_iter()
        .filter_map(|path| read_taint_iris_next_source_file(path, max_bytes_per_file))
        .collect())
}

pub(crate) fn collect_taint_iris_next_source_paths(
    root: &Path,
    max_files: Option<usize>,
) -> Result<Vec<TaintIrisNextSourcePath>> {
    let mut paths = Vec::new();
    collect_taint_iris_next_source_paths_inner(root, root, max_files, &mut paths)?;
    Ok(paths)
}

fn collect_taint_iris_next_source_paths_inner(
    root: &Path,
    dir: &Path,
    max_files: Option<usize>,
    paths: &mut Vec<TaintIrisNextSourcePath>,
) -> Result<()> {
    if reached_walker_cap(paths.len(), max_files) {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if reached_walker_cap(paths.len(), max_files) {
            break;
        }
        collect_source_path_entry(root, entry, max_files, paths)?;
    }
    Ok(())
}

fn collect_source_path_entry(
    root: &Path,
    entry: fs::DirEntry,
    max_files: Option<usize>,
    paths: &mut Vec<TaintIrisNextSourcePath>,
) -> Result<()> {
    let path = entry.path();
    if should_skip_path(&entry.file_name().to_string_lossy()) {
        return Ok(());
    }
    let Ok(file_type) = entry.file_type() else {
        return Ok(());
    };
    if file_type.is_dir() {
        return collect_taint_iris_next_source_paths_inner(root, &path, max_files, paths);
    }
    if collectable_source_file(&file_type, &path) {
        paths.push(source_path_record(root, path));
    }
    Ok(())
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
    path: TaintIrisNextSourcePath,
    max_bytes_per_file: usize,
) -> Option<TaintIrisNextSourceFile> {
    let raw = fs::read(&path.absolute_path).ok()?;
    if raw.iter().take(4096).any(|byte| *byte == 0) {
        return None;
    }
    let text = String::from_utf8_lossy(&raw[..raw.len().min(max_bytes_per_file)]).to_string();
    Some(TaintIrisNextSourceFile {
        relative_path: path.relative_path,
        language: path.language,
        lines: text.lines().map(ToString::to_string).collect(),
    })
}

fn reached_walker_cap(current: usize, max_files: Option<usize>) -> bool {
    matches!(max_files, Some(cap) if current >= cap)
}

pub(crate) fn detect_taint_iris_next_languages(root: &Path) -> Result<Vec<String>> {
    // Language detection only needs a representative sample; capping at 600
    // files keeps the language-fingerprinting cheap on huge repos and never
    // affects taint-hunt scope (which uses the unbounded walker below).
    Ok(collect_taint_iris_next_source_files(root, Some(600), 1024)?
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
