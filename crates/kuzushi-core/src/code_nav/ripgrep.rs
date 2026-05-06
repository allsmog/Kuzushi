//! `find_references` via `rg` shell-out.
//!
//! Why ripgrep instead of the `grep` crate: the binary has battle-tested
//! `--ignore` handling that respects `.gitignore`, `--type` filters, and
//! gives consistent output with `--json`. The crate version requires
//! reproducing that logic ourselves.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::canonicalise::canonicalise_within;

/// Hard cap on result count — prevents the model from being flooded by a
/// generic name (e.g. `i`, `tmp`, or a popular type).
pub const MAX_REFERENCES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesInput {
    pub symbol: String,
    /// Optional file/directory to scope to (relative to root). Defaults to root.
    #[serde(default)]
    pub scope: Option<String>,
    /// Optional rg `--type` filter (e.g. `c`, `rust`, `java`).
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceHit {
    pub file: String,
    pub line: u32,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesOutput {
    pub symbol: String,
    pub hits: Vec<ReferenceHit>,
    /// Number of hits the search produced before truncation.
    pub total_hits: usize,
    pub truncated: bool,
}

/// Where the `rg` binary lives. Override via `KUZUSHI_RIPGREP_BIN` for
/// tests or non-standard installations.
fn ripgrep_binary() -> String {
    std::env::var("KUZUSHI_RIPGREP_BIN").unwrap_or_else(|_| "rg".to_string())
}

pub fn find_references(root: &Path, input: &FindReferencesInput) -> Result<FindReferencesOutput> {
    let symbol = input.symbol.trim();
    anyhow::ensure!(!symbol.is_empty(), "find_references: symbol must be non-empty");
    anyhow::ensure!(
        !symbol.contains('\n') && !symbol.contains('\0'),
        "find_references: symbol may not contain newlines or null bytes"
    );

    // Resolve scope under root for the canonicalisation guard.
    let scope_path = match input.scope.as_deref() {
        Some(scope) if !scope.trim().is_empty() => canonicalise_within(root, scope)
            .with_context(|| format!("find_references: scope {scope:?}"))?,
        _ => root
            .canonicalize()
            .with_context(|| format!("find_references: bad root {}", root.display()))?,
    };

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
    if let Some(lang) = input.language.as_deref() {
        let trimmed = lang.trim();
        if !trimmed.is_empty() {
            // rg --type accepts predefined names; if the model passes an
            // unknown one we let rg fail with a structured error.
            cmd.arg("--type").arg(trimmed);
        }
    }
    cmd.arg("--").arg(symbol).arg(&scope_path);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().with_context(|| {
        format!(
            "find_references: could not invoke {} — install ripgrep or set KUZUSHI_RIPGREP_BIN",
            ripgrep_binary()
        )
    })?;
    if !output.status.success() && output.stdout.is_empty() {
        // exit 1 = no matches → not an error. Anything else with stderr is.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() && !output.status.code().is_some_and(|c| c == 1) {
            anyhow::bail!("find_references: rg failed: {}", stderr.trim());
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

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

    let truncated = total > MAX_REFERENCES;
    Ok(FindReferencesOutput {
        symbol: input.symbol.clone(),
        hits,
        total_hits: total,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn rg_available() -> bool {
        Command::new(ripgrep_binary())
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn finds_a_symbol_in_a_small_workspace() {
        if !rg_available() {
            eprintln!("rg not on PATH; skipping");
            return;
        }
        let tmp = tempdir().unwrap();
        fs::write(
            tmp.path().join("foo.rs"),
            "fn target() {}\nfn other() { target() }\n",
        )
        .unwrap();
        let out = find_references(
            tmp.path(),
            &FindReferencesInput {
                symbol: "target".to_string(),
                scope: None,
                language: None,
            },
        )
        .unwrap();
        assert_eq!(out.hits.len(), 2);
        assert!(out.hits.iter().any(|h| h.line == 1));
        assert!(out.hits.iter().any(|h| h.line == 2));
        assert!(!out.truncated);
    }

    #[test]
    fn empty_symbol_is_rejected() {
        let tmp = tempdir().unwrap();
        let err = find_references(
            tmp.path(),
            &FindReferencesInput {
                symbol: "  ".to_string(),
                scope: None,
                language: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn newline_symbol_is_rejected() {
        let tmp = tempdir().unwrap();
        let err = find_references(
            tmp.path(),
            &FindReferencesInput {
                symbol: "foo\nbar".to_string(),
                scope: None,
                language: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("newlines"));
    }

    #[test]
    fn scope_outside_root_is_rejected() {
        let tmp = tempdir().unwrap();
        let inner = tmp.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(tmp.path().join("outside.rs"), "fn target() {}").unwrap();
        let err = find_references(
            &inner,
            &FindReferencesInput {
                symbol: "target".to_string(),
                scope: Some("../outside.rs".to_string()),
                language: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("scope"));
    }

    #[test]
    fn truncates_above_max_references() {
        if !rg_available() {
            return;
        }
        let tmp = tempdir().unwrap();
        // Spam 250 occurrences of the same word across 250 files.
        for i in 0..250 {
            fs::write(
                tmp.path().join(format!("f{i}.rs")),
                "// floodword target_word\n",
            )
            .unwrap();
        }
        let out = find_references(
            tmp.path(),
            &FindReferencesInput {
                symbol: "target_word".to_string(),
                scope: None,
                language: None,
            },
        )
        .unwrap();
        assert!(out.hits.len() <= MAX_REFERENCES);
        assert!(out.truncated);
    }
}
