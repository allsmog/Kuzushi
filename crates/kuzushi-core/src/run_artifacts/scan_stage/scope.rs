use super::ScanStageScope;
use std::path::Path;

impl ScanStageScope {
    /// Pure containment check against the recorded discovery scope. Unknown,
    /// escaping, and absolute outside-target paths cannot establish coverage.
    pub fn covers_file(&self, file_path: &str) -> bool {
        scan_paths_cover_file(&self.target, &self.paths, file_path)
    }
}

pub(crate) fn scan_paths_cover_file(target: &str, paths: &[String], file: &str) -> bool {
    let Some(relative) = target_relative(target, file) else { return false; };
    paths.is_empty() || paths.iter().any(|scope| path_is_within(&relative, scope))
}

fn target_relative(target: &str, file: &str) -> Option<String> {
    let path = Path::new(file);
    let stripped = match path.strip_prefix(target) {
        Ok(stripped) => stripped,
        Err(_) if path.is_absolute() => return None,
        Err(_) => path,
    };
    lexically_normalized(&stripped.to_string_lossy().replace('\\', "/"))
}

fn lexically_normalized(path: &str) -> Option<String> {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {},
            ".." => { segments.pop()?; },
            other => segments.push(other),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

fn path_is_within(path: &str, scope: &str) -> bool {
    if scope == "." { return true; }
    let Some(scope) = lexically_normalized(scope) else { return false; };
    path == scope || path.strip_prefix(&scope).is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coverage_refuses_unknown_and_escaping_paths_even_for_whole_target() {
        for paths in [vec![], vec!["lib".into()]] {
            assert!(scan_paths_cover_file("/repo", &paths, "lib/x.rs"));
            for file in ["", ".", "../x.rs", "/elsewhere/lib/x.rs"] {
                assert!(!scan_paths_cover_file("/repo", &paths, file), "{file}");
            }
        }
        assert!(!scan_paths_cover_file("/repo", &["lib".into()], "library/x.rs"));
        assert!(!scan_paths_cover_file("/repo", &["lib/..".into()], "x.rs"));
    }
}
