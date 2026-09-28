use super::*;

/// Walk `dir` for manifests the selected kinds cover. A directory the process
/// cannot list is a hole in the scan, not an empty subtree, so it is recorded
/// in `gaps` rather than dropped: the report has to be able to say the tree
/// was not fully read.
pub(crate) fn collect_iac_files(
    root: &Path,
    dir: &Path,
    options: &IacScanOptions,
    out: &mut Vec<PathBuf>,
    gaps: &mut CoverageGaps,
) -> Result<()> {
    let Some(mut entries) = read_dir_entries(root, dir, gaps) else {
        return Ok(());
    };
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if should_skip_dir(&name) {
            continue;
        }

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                gaps.record(root, &path, CoverageGapKind::Entry, &error);
                continue;
            }
        };
        if file_type.is_dir() {
            collect_iac_files(root, &path, options, out, gaps)?;
        } else if file_type.is_file()
            && classify_iac_file(root, &path).is_some_and(|kind| options.kind.includes(kind))
        {
            out.push(path);
        }
    }

    Ok(())
}

pub(crate) fn classify_iac_file(root: &Path, path: &Path) -> Option<IacScanKind> {
    let file_name = path.file_name()?.to_string_lossy();
    if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
        return Some(IacScanKind::Dockerfile);
    }

    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut components = rel.components().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(name.to_string_lossy().to_string()),
        _ => None,
    });
    if components.next().as_deref() == Some(".github")
        && components.next().as_deref() == Some("workflows")
        && matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        )
    {
        return Some(IacScanKind::GithubActions);
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("tf") {
        return Some(IacScanKind::Terraform);
    }

    None
}
