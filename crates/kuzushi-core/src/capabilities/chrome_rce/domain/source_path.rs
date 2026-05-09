use std::path::Path;

pub(crate) fn is_source_path(root: &Path, path: &Path) -> bool {
    has_source_extension(path) && is_chrome_surface_path(&repo_relative_path(root, path))
}

fn has_source_extension(path: &Path) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    SOURCE_EXTENSIONS.contains(&ext)
}

fn repo_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn is_chrome_surface_path(relative: &str) -> bool {
    CHROME_SURFACE_MARKERS
        .iter()
        .any(|marker| relative.contains(marker))
}

const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hh", "hpp"];
const CHROME_SURFACE_MARKERS: &[&str] = &["/ipc/", "/mojo/", "/services/", "/sandbox/", "broker"];
