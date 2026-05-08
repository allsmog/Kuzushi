use super::*;

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisNextSourceFile {
    pub(in crate::modules) relative_path: String,
    pub(in crate::modules) language: String,
    pub(in crate::modules) lines: Vec<String>,
}

pub(in crate::modules) fn collect_taint_iris_next_source_files(
    root: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
) -> Result<Vec<TaintIrisNextSourceFile>> {
    let mut files = Vec::new();
    collect_taint_iris_next_source_files_inner(
        root,
        root,
        max_files,
        max_bytes_per_file,
        &mut files,
    )?;
    Ok(files)
}

pub(in crate::modules) fn collect_taint_iris_next_source_files_inner(
    root: &Path,
    dir: &Path,
    max_files: usize,
    max_bytes_per_file: usize,
    files: &mut Vec<TaintIrisNextSourceFile>,
) -> Result<()> {
    if files.len() >= max_files {
        return Ok(());
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        if files.len() >= max_files {
            break;
        }
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_taint_iris_next_source_files_inner(
                root,
                &path,
                max_files,
                max_bytes_per_file,
                files,
            )?;
            continue;
        }
        if !file_type.is_file() || !is_agentic_context_file(&path) {
            continue;
        }
        let raw = fs::read(&path).unwrap_or_default();
        if raw.iter().take(4096).any(|byte| *byte == 0) {
            continue;
        }
        let text = String::from_utf8_lossy(&raw[..raw.len().min(max_bytes_per_file)]).to_string();
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let language = language_for_path(&path);
        files.push(TaintIrisNextSourceFile {
            relative_path,
            language,
            lines: text.lines().map(ToString::to_string).collect(),
        });
    }
    Ok(())
}

pub(in crate::modules) fn detect_taint_iris_next_languages(root: &Path) -> Result<Vec<String>> {
    Ok(collect_taint_iris_next_source_files(root, 600, 1024)?
        .into_iter()
        .map(|file| file.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

pub(in crate::modules) fn language_for_path(path: &Path) -> String {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "js" | "jsx" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "rb" => "ruby",
        "php" => "php",
        "java" => "java",
        "go" => "go",
        "rs" => "rust",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        _ => "unknown",
    }
    .to_string()
}
