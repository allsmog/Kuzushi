use super::*;


fn fixture_target() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("src/app.py"), "a\nb\nc\n").unwrap();
    temp
}

fn document(files: &[&str]) -> Value {
    json!({
        "methodology": "stride",
        "threats": [{
            "id": "T-001",
            "title": "traversal",
            "affectedFiles": files,
            "evidenceAnchors": [{"filePath": files[0], "startLine": 2, "description": "join"}],
        }],
        "attackSurface": {
            "entryPoints": [{"name": "download", "evidence": format!("{}:1", files[0])}],
        },
    })
}

#[test]
fn path_refs_cover_affected_files_evidence_strings_and_anchors() {
    let refs = cited_path_refs(&document(&["src/app.py"]));
    assert!(refs.iter().any(|r| r.path == "src/app.py" && r.line == Some(2)));
    assert!(refs.iter().any(|r| r.path == "src/app.py" && r.line == Some(1)));
    assert!(refs.iter().any(|r| r.path == "src/app.py" && r.line.is_none()));
}

#[test]
fn existing_citations_verify_and_missing_citations_fail() {
    let target = fixture_target();
    let good = verify_threat_model_document(&document(&["src/app.py"]), target.path()).unwrap();
    assert_eq!(good.verdict, "verified");
    assert_eq!(good.missing_count, 0);
    assert_eq!(
        good.revision.matches, None,
        "non-git target is tri-state unknown, not a failure"
    );

    let bad = verify_threat_model_document(&document(&["src/gone.py"]), target.path()).unwrap();
    assert_eq!(bad.verdict, "failed");
    assert!(bad.missing_count >= 1);
    assert!(bad.missing.iter().any(|entry| entry.contains("src/gone.py")));
}

#[test]
fn out_of_range_lines_and_escaping_paths_are_flagged() {
    let target = fixture_target();
    let mut doc = document(&["src/app.py"]);
    doc["threats"][0]["evidenceAnchors"][0]["startLine"] = json!(999);
    let verification = verify_threat_model_document(&doc, target.path()).unwrap();
    assert_eq!(verification.verdict, "failed");
    assert!(verification.missing.iter().any(|entry| entry.contains("999")));

    let hostile = document(&["../outside.py"]);
    let verification = verify_threat_model_document(&hostile, target.path()).unwrap();
    assert!(verification
        .missing
        .iter()
        .any(|entry| entry.contains("escapes the target root")));
}

#[test]
fn revision_mismatch_in_a_git_checkout_is_stale_and_warns() {
    let target = fixture_target();
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(target.path())
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);

    let mut doc = document(&["src/app.py"]);
    doc["provenance"] = json!({"revision": "0000000000000000000000000000000000000000"});
    let verification = verify_threat_model_document(&doc, target.path()).unwrap();
    assert_eq!(verification.verdict, "stale");
    assert_eq!(verification.revision.matches, Some(false));
    let warning = verification_warning(&doc, target.path()).unwrap();
    assert!(warning.contains("may be stale"), "warning: {warning}");
}

#[test]
fn stamped_failed_verdict_warns_without_revision_drift() {
    let target = fixture_target();
    let mut doc = document(&["src/app.py"]);
    let mut verification = verify_threat_model_document(&doc, target.path()).unwrap();
    verification.verdict = "failed".to_string();
    stamp_verification(&mut doc, &verification);
    let warning = verification_warning(&doc, target.path()).unwrap();
    assert!(warning.contains("cited paths missing"));
}
