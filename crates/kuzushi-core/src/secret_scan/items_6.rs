use super::prelude::*;
use super::*;

pub(crate) fn canonical_directory(target: &Path) -> Result<PathBuf> {
    let path = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Could not resolve current directory")?
            .join(target)
    };
    if !path.exists() {
        anyhow::bail!("secret-scan: target is not a directory: {}", path.display());
    }
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("secret-scan: failed to resolve {}", path.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "secret-scan: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

pub(crate) fn collect_files(
    dir: &Path,
    options: &SecretScanOptions,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if options.exclude_dirs.contains(file_name.as_str()) {
                continue;
            }
            collect_files(&path, options, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }

    Ok(())
}

pub(crate) fn detect_secrets_in_text(text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    detect_token_shapes(text, &mut hits);
    detect_assignments(
        text,
        &[
            "aws_secret_access_key",
            "aws-secret-access-key",
            "aws_secret_key",
            "aws-secret-key",
            "aws_secret",
            "aws-secret",
        ],
        aws_secret_key_detector(),
        AssignmentMode::OptionalQuote,
        is_base64_secret_char,
        &mut hits,
    );
    detect_assignments(
        text,
        &[
            "password",
            "passwd",
            "api_key",
            "api-key",
            "secret",
            "secret_key",
            "secret-key",
            "access_token",
            "access-token",
            "auth_token",
            "auth-token",
        ],
        generic_secret_assignment_detector(),
        AssignmentMode::RequiredQuote,
        is_generic_secret_char,
        &mut hits,
    );
    detect_pem_private_keys(text, &mut hits);
    hits.sort_by_key(|hit| hit.index);
    hits
}

pub(crate) fn detect_token_shapes(text: &str, hits: &mut Vec<SecretHit>) {
    let bytes = text.as_bytes();
    let mut start = None;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_token_char(byte) {
            if start.is_none() {
                start = Some(index);
            }
            continue;
        }

        if let Some(token_start) = start.take() {
            classify_token(text, token_start, index, hits);
        }
    }

    if let Some(token_start) = start {
        classify_token(text, token_start, text.len(), hits);
    }
}
