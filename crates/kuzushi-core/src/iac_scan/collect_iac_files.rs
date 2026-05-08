use super::*;

pub(crate) fn collect_iac_files(
    root: &Path,
    dir: &Path,
    options: &IacScanOptions,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if should_skip_dir(&name) {
            continue;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_iac_files(root, &path, options, out)?;
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
