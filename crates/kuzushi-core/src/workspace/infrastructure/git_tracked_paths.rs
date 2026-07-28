use std::path::Path;
use std::process::Command;

/// Returns tracked paths in Git index order, or `None` when Git cannot provide
/// a non-empty index so inventory can fall back to filesystem enumeration.
pub(crate) fn git_tracked_relative_paths(root: &Path) -> Option<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect::<Vec<_>>();
    (!paths.is_empty()).then_some(paths)
}
