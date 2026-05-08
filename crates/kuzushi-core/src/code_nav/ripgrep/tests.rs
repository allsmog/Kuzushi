#[cfg(test)]
mod tests {
    use super::super::*;
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
