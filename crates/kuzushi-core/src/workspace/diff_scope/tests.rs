#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use serde_json::{json, Value};
    use tempfile::tempdir;

    use super::super::*;
    use crate::findings::{Severity, StaticProofState};

    #[test]
    fn diff_status_helpers_cover_all_stable_labels() {
        assert_eq!(DiffFindingStatus::New.as_str(), "new");
        assert_eq!(DiffFindingStatus::Existing.as_str(), "existing");
        assert_eq!(DiffFindingStatus::NotSeen.as_str(), "not-seen");
        assert_eq!(
            DiffFindingStatus::ChangedContext.as_str(),
            "changed-context"
        );

        assert_eq!(status_from_name_status("A"), DiffFileStatus::Added);
        assert_eq!(status_from_name_status("M"), DiffFileStatus::Modified);
        assert_eq!(status_from_name_status("D"), DiffFileStatus::Deleted);
        assert_eq!(status_from_name_status("R100"), DiffFileStatus::Renamed);
        assert_eq!(status_from_name_status("C075"), DiffFileStatus::Copied);
        assert_eq!(status_from_name_status("T"), DiffFileStatus::TypeChanged);
        assert_eq!(status_from_name_status("?"), DiffFileStatus::Unknown);
    }

    #[test]
    fn diff_scope_serializes_not_seen_and_reads_legacy_fixed() {
        let status = serde_json::from_value::<DiffFindingStatus>(json!("fixed")).unwrap();
        assert_eq!(status, DiffFindingStatus::NotSeen);
        assert_eq!(
            serde_json::to_value(DiffFindingStatus::NotSeen).unwrap(),
            json!("not-seen")
        );

        let summary = DiffScopeSummary {
            not_seen_findings: 2,
            ..DiffScopeSummary::default()
        };
        let serialized = serde_json::to_value(summary).unwrap();
        assert_eq!(
            serialized.get("notSeenFindings").and_then(Value::as_u64),
            Some(2)
        );
        assert!(serialized.get("fixedFindings").is_none());

        let legacy_summary = serde_json::from_value::<DiffScopeSummary>(json!({
            "changedFiles": 0,
            "changedRanges": 0,
            "deletedRanges": 0,
            "contextItems": 0,
            "newFindings": 0,
            "existingFindings": 0,
            "fixedFindings": 3,
            "changedContextFindings": 0
        }))
        .unwrap();
        assert_eq!(legacy_summary.not_seen_findings, 3);
    }

    #[cfg(unix)]
    fn init_git_repo(dir: &Path) {
        for args in [
            vec!["init"],
            vec!["config", "user.email", "kuzushi@example.test"],
            vec!["config", "user.name", "Kuzushi Test"],
            // Stay hermetic against a host git config that forces signing.
            vec!["config", "commit.gpgsign", "false"],
            vec!["config", "tag.gpgsign", "false"],
            vec!["add", "."],
            vec!["commit", "-m", "base"],
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn git_diff_files_returns_committed_changes() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("a.c"), "void a(){}\n").unwrap();
        init_git_repo(temp.path());
        let base = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(base.status.success());
        let base = String::from_utf8(base.stdout).unwrap().trim().to_string();

        fs::write(temp.path().join("a.c"), "void a2(){}\n").unwrap();
        fs::write(temp.path().join("b.c"), "void b(){}\n").unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "change"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());

        let scope = git_diff_files(temp.path(), &base, false).unwrap();
        assert_eq!(
            scope.files,
            vec![PathBuf::from("a.c"), PathBuf::from("b.c")]
        );
        assert!(scope.contains_path(Path::new("a.c")));
    }

    #[cfg(unix)]
    #[test]
    fn git_diff_files_rejects_ref_injection_chars() {
        let temp = tempdir().unwrap();
        for value in ["abc; rm -rf /", "abc | cat", "abc`whoami`"] {
            let err = git_diff_files(temp.path(), value, false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("forbidden characters"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn whitebox_diff_scope_computes_ranges_context_and_finding_tags() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/app.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/users', function users(req, res) {",
                "  const id = req.query.id;",
                "  const sql = `select * from users where id = ${id}`;",
                "  eval(req.query.cmd);",
                "  return res.send('ok');",
                "});",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), "base\n").unwrap();
        init_git_repo(temp.path());
        fs::write(
            temp.path().join("src/app.js"),
            [
                "const express = require('express');",
                "const app = express();",
                "app.get('/users', function users(req, res) {",
                "  const id = req.query.id;",
                "  const sql = `select * from users where id = ${id}`;",
                "  db.query(sql);",
                "  return res.send('ok');",
                "});",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(temp.path().join("README.md"), "base\nchanged\n").unwrap();
        let output = Command::new("git")
            .args(["add", "."])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false", "commit", "-m", "pr"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success());

        let mut new_finding = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/app.js",
            6,
            Some(6),
            Severity::High,
            "SQL query uses request input",
        );
        new_finding.set_static_proof_state(StaticProofState::SourceSinkLinked);
        let context_finding = Finding::new_tool(
            "semgrep",
            "js/headers",
            "src/app.js",
            2,
            Some(2),
            Severity::Low,
            "Header setup needs review",
        );
        let old_not_seen = Finding::new_tool(
            "semgrep",
            "js/missing-query",
            "src/app.js",
            6,
            Some(6),
            Severity::Medium,
            "Previous finding on old changed line",
        );

        let report = build_whitebox_diff_scope_report(
            temp.path(),
            "HEAD~1",
            &[new_finding.clone(), context_finding.clone()],
            &[old_not_seen],
        )
        .unwrap();

        assert!(report.no_remote_provider_required);
        assert_eq!(report.summary.changed_files, 2);
        assert!(report
            .changed_files
            .iter()
            .any(|file| file.path == "src/app.js" && !file.changed_ranges.is_empty()));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Route
                && item.path == "src/app.js"
                && item.detail.contains("/users")
        }));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Caller && item.detail.contains("function users")
        }));
        assert!(report.context.iter().any(|item| {
            item.kind == DiffContextKind::Callee && item.detail.contains("db.query")
        }));
        assert_eq!(
            report
                .finding_tags
                .iter()
                .find(|tag| tag.fingerprint == new_finding.fingerprint)
                .map(|tag| tag.status),
            Some(DiffFindingStatus::New)
        );
        assert_eq!(
            report
                .finding_tags
                .iter()
                .find(|tag| tag.fingerprint == context_finding.fingerprint)
                .map(|tag| tag.status),
            Some(DiffFindingStatus::ChangedContext)
        );
        assert_eq!(report.not_seen_findings.len(), 1);
        assert_eq!(
            report.not_seen_findings[0].status,
            DiffFindingStatus::NotSeen
        );
        let report_json = serde_json::to_value(&report).unwrap();
        assert!(report_json.get("notSeenFindings").is_some());
        assert!(report_json.get("fixedFindings").is_none());
        assert_eq!(
            report_json
                .pointer("/summary/notSeenFindings")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            report_json
                .pointer("/notSeenFindings/0/status")
                .and_then(Value::as_str),
            Some("not-seen")
        );
    }
}

#[cfg(test)]
mod since_scope_tests {
    use super::super::*;
    use std::fs;
    use std::process::{Command, Stdio};
    use tempfile::tempdir;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.email=test@example.com", "-c", "user.name=test"])
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git binary required for these tests");
        assert!(status.success(), "git {args:?} in {} failed", dir.display());
    }

    fn git_capture(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("git binary required");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn make_repo() -> (tempfile::TempDir, String) {
        let tmp = tempdir().unwrap();
        git(tmp.path(), &["init", "-q", "-b", "main"]);
        fs::write(tmp.path().join("a.c"), "void a(){}\n").unwrap();
        fs::write(tmp.path().join("b.c"), "void b(){}\n").unwrap();
        git(tmp.path(), &["add", "."]);
        git(
            tmp.path(),
            &["commit", "-q", "-m", "first", "--no-gpg-sign"],
        );
        let head = git_capture(tmp.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        (tmp, head)
    }

    #[test]
    fn git_diff_files_returns_changed_files_against_committed_base() {
        let (tmp, base) = make_repo();
        fs::write(tmp.path().join("a.c"), "void a_v2(){}\n").unwrap();
        fs::write(tmp.path().join("c.c"), "void c(){}\n").unwrap();
        git(tmp.path(), &["add", "."]);
        git(
            tmp.path(),
            &["commit", "-q", "-m", "second", "--no-gpg-sign"],
        );

        let scope = git_diff_files(tmp.path(), &base, false).unwrap();
        let names = scope
            .files
            .iter()
            .map(|path| path.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["a.c", "c.c"]);
    }

    #[test]
    fn git_diff_files_include_worktree_picks_up_uncommitted_changes() {
        let (tmp, base) = make_repo();
        fs::write(
            tmp.path().join("b.c"),
            "// edited but not committed\nvoid b(){}\n",
        )
        .unwrap();
        let committed_only = git_diff_files(tmp.path(), &base, false).unwrap();
        assert!(committed_only.files.is_empty());
        let with_worktree = git_diff_files(tmp.path(), &base, true).unwrap();
        let names = with_worktree
            .files
            .iter()
            .map(|path| path.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["b.c"]);
    }

    #[test]
    fn git_diff_files_rejects_injection_chars_in_ref() {
        let tmp = tempdir().unwrap();
        for value in ["abc; rm -rf /", "abc | cat", "abc`whoami`"] {
            let err = git_diff_files(tmp.path(), value, false)
                .unwrap_err()
                .to_string();
            assert!(err.contains("forbidden characters"), "{err}");
        }
    }

    #[test]
    fn diff_scope_contains_path_and_prefix() {
        let scope = DiffScope {
            files: vec![PathBuf::from("src/foo.c"), PathBuf::from("src/bar.c")],
            since_ref: "main".to_string(),
            include_worktree: false,
        };
        assert!(scope.contains_path(Path::new("src/foo.c")));
        assert!(!scope.contains_path(Path::new("src/baz.c")));
        assert!(scope.contains_prefix(Path::new("src")));
        assert!(!scope.contains_prefix(Path::new("tests")));
    }

    #[test]
    fn since_ref_that_parses_as_a_git_option_is_rejected() {
        let tmp = tempdir().unwrap();
        for hostile in ["--output=/tmp/pwn", "-O/tmp/pwn", "", "a\nb"] {
            let error = git_diff_files(tmp.path(), hostile, false)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("must not start with '-'")
                    || error.contains("is empty")
                    || error.contains("control characters"),
                "{hostile:?}: {error}"
            );
        }
        assert!(!Path::new("/tmp/pwn").exists());
    }
}
