use super::*;

pub fn find_references(root: &Path, input: &FindReferencesInput) -> Result<FindReferencesOutput> {
    let symbol = validated_symbol(&input.symbol)?;
    let scope_path = reference_scope_path(root, input)?;
    let output = run_ripgrep_reference_search(&scope_path, symbol, input.language.as_deref())?;
    validate_ripgrep_reference_output(&output)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let (hits, total) = parse_reference_hits(&stdout, &canonical_root);
    let truncated = total > MAX_REFERENCES;
    Ok(FindReferencesOutput {
        symbol: input.symbol.clone(),
        hits,
        total_hits: total,
        truncated,
    })
}

pub(crate) fn validated_symbol(symbol: &str) -> Result<&str> {
    let symbol = symbol.trim();
    anyhow::ensure!(
        !symbol.is_empty(),
        "find_references: symbol must be non-empty"
    );
    anyhow::ensure!(
        !symbol.contains('\n') && !symbol.contains('\0'),
        "find_references: symbol may not contain newlines or null bytes"
    );
    Ok(symbol)
}

pub(crate) fn reference_scope_path(
    root: &Path,
    input: &FindReferencesInput,
) -> Result<std::path::PathBuf> {
    match input.scope.as_deref() {
        Some(scope) if !scope.trim().is_empty() => canonicalise_within(root, scope)
            .with_context(|| format!("find_references: scope {scope:?}")),
        _ => root
            .canonicalize()
            .with_context(|| format!("find_references: bad root {}", root.display())),
    }
}

pub(crate) fn run_ripgrep_reference_search(
    scope_path: &Path,
    symbol: &str,
    language: Option<&str>,
) -> Result<std::process::Output> {
    let mut cmd = Command::new(ripgrep_binary());
    cmd.arg("--no-messages")
        .arg("--with-filename")
        .arg("--line-number")
        .arg("--word-regexp")
        .arg("--max-count")
        .arg(format!("{}", MAX_REFERENCES + 1))
        .arg("--max-filesize")
        .arg("4M")
        .arg("--no-heading")
        .arg("--color")
        .arg("never");
    if let Some(lang) = language {
        let trimmed = lang.trim();
        if !trimmed.is_empty() {
            cmd.arg("--type").arg(trimmed);
        }
    }
    cmd.arg("--").arg(symbol).arg(&scope_path);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    cmd.output().with_context(|| {
        format!(
            "find_references: could not invoke {} — install ripgrep or set KUZUSHI_RIPGREP_BIN",
            ripgrep_binary()
        )
    })
}

pub(crate) fn validate_ripgrep_reference_output(output: &std::process::Output) -> Result<()> {
    if !output.status.success() && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() && !output.status.code().is_some_and(|c| c == 1) {
            anyhow::bail!("find_references: rg failed: {}", stderr.trim());
        }
    }
    Ok(())
}

pub(crate) fn parse_reference_hits(
    stdout: &str,
    canonical_root: &Path,
) -> (Vec<ReferenceHit>, usize) {
    let mut hits: Vec<ReferenceHit> = Vec::new();
    let mut total = 0usize;
    for line in stdout.lines() {
        total += 1;
        if hits.len() >= MAX_REFERENCES {
            continue;
        }
        let Some((path_part, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((line_no_part, snippet)) = rest.split_once(':') else {
            continue;
        };
        let Ok(line_no) = line_no_part.parse::<u32>() else {
            continue;
        };
        // Relativise file path back to the workspace root for stable output.
        let path_rel = match Path::new(path_part).strip_prefix(&canonical_root) {
            Ok(rel) => rel.to_string_lossy().into_owned(),
            Err(_) => path_part.to_string(),
        };
        hits.push(ReferenceHit {
            file: path_rel,
            line: line_no,
            snippet: snippet.trim().to_string(),
        });
    }
    (hits, total)
}
