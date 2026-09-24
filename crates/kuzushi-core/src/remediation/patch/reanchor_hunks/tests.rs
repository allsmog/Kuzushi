use super::*;

fn source(content: &'static str) -> impl Fn(&str) -> Option<String> {
    move |path| (path == "lib/app.ts").then(|| content.to_string())
}

const FILE: &str = "one\ntwo\nthree\nfour\nKEY = 'secret'\nsix\nseven\neight\nnine\n";

#[test]
fn zero_context_hunk_gains_real_context_and_exact_lines() {
    let diff = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -1,1 +1,1 @@\n-KEY = 'secret'\n+KEY = env()\n";

    let fixed = reanchor_hunks(diff, &source(FILE));

    assert_eq!(
        fixed,
        "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -2,7 +2,7 @@\n two\n three\n four\n-KEY = 'secret'\n+KEY = env()\n six\n seven\n eight\n"
    );
}

#[test]
fn leading_only_context_is_balanced_and_later_hunks_shift() {
    let diff = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -4,2 +4,3 @@ fn x\n four\n-KEY = 'secret'\n+KEY = env()\n+EXTRA = 1\n@@ -9,1 +10,1 @@\n-nine\n+NINE\n";

    let fixed = reanchor_hunks(diff, &source(FILE));

    assert!(fixed.contains("@@ -1,8 +1,9 @@ fn x\n one\n two\n three\n four\n-KEY"), "{fixed}");
    // The second hunk's context was already shown by the first, so it starts
    // at its own change and is shifted by the first hunk's extra line.
    assert!(fixed.ends_with(" eight\n@@ -9,1 +10,1 @@\n-nine\n+NINE\n"), "{fixed}");
}

#[test]
fn ambiguous_unmatched_or_special_sections_pass_through_unchanged() {
    let repeated = "x\nx\nx\n";
    let twice = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -1,1 +1,1 @@\n-x\n+y\n";
    assert_eq!(reanchor_hunks(twice, &source(repeated)), twice);

    let missing = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -1,1 +1,1 @@\n-absent\n+y\n";
    assert_eq!(reanchor_hunks(missing, &source(FILE)), missing);

    let created = "--- /dev/null\n+++ b/lib/app.ts\n@@ -0,0 +1,1 @@\n+new\n";
    assert_eq!(reanchor_hunks(created, &source(FILE)), created);

    let no_newline = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -9,1 +9,1 @@\n-nine\n\\ No newline at end of file\n+NINE\n";
    assert_eq!(reanchor_hunks(no_newline, &source(FILE)), no_newline);
}

#[test]
fn git_headers_and_other_files_are_preserved_around_a_rewrite() {
    let diff = "diff --git a/lib/app.ts b/lib/app.ts\nindex 1..2 100644\n--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -1 +1 @@\n-KEY = 'secret'\n+KEY = env()\ndiff --git a/other.ts b/other.ts\n--- a/other.ts\n+++ b/other.ts\n@@ -1 +1 @@\n-a\n+b\n";

    let fixed = reanchor_hunks(diff, &source(FILE));

    assert!(fixed.starts_with("diff --git a/lib/app.ts b/lib/app.ts\nindex 1..2 100644\n--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -2,7 +2,7 @@\n"), "{fixed}");
    assert!(fixed.ends_with("diff --git a/other.ts b/other.ts\n--- a/other.ts\n+++ b/other.ts\n@@ -1 +1 @@\n-a\n+b\n"), "{fixed}");
}

#[test]
fn two_hunk_reanchored_diff_applies_with_git() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join("lib")).unwrap();
    std::fs::write(repo.path().join("lib/app.ts"), FILE).unwrap();
    let diff = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -4,2 +4,3 @@\n four\n-KEY = 'secret'\n+KEY = env()\n+EXTRA = 1\n@@ -9,1 +10,1 @@\n-nine\n+NINE\n";
    let fixed = reanchor_hunks_in_checkout(repo.path(), diff);
    std::fs::write(repo.path().join("fixed.diff"), &fixed).unwrap();
    let output = std::process::Command::new("git")
        .args(["apply", "fixed.diff"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}\n{fixed}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        std::fs::read_to_string(repo.path().join("lib/app.ts")).unwrap(),
        "one\ntwo\nthree\nfour\nKEY = env()\nEXTRA = 1\nsix\nseven\neight\nNINE\n"
    );
}

#[test]
fn reanchored_diff_applies_with_git() {
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join("lib")).unwrap();
    std::fs::write(repo.path().join("lib/app.ts"), FILE).unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(repo.path())
            .output()
            .unwrap()
    };
    git(&["init", "-q"]);
    let raw = "--- a/lib/app.ts\n+++ b/lib/app.ts\n@@ -5,1 +5,1 @@\n-KEY = 'secret'\n+KEY = env()\n";
    std::fs::write(repo.path().join("raw.diff"), raw).unwrap();
    assert!(!git(&["apply", "--check", "raw.diff"]).status.success(), "zero-context hunk is the failure being fixed");

    let fixed = reanchor_hunks_in_checkout(repo.path(), raw);
    std::fs::write(repo.path().join("fixed.diff"), &fixed).unwrap();
    let check = git(&["apply", "--check", "fixed.diff"]);
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
}

#[test]
fn checkout_reads_refuse_escapes_and_symlinks() {
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("inside.ts"), "x\n").unwrap();
    assert_eq!(read_checkout_file(repo.path(), "inside.ts").as_deref(), Some("x\n"));
    assert_eq!(read_checkout_file(repo.path(), "../inside.ts"), None);
    assert_eq!(read_checkout_file(repo.path(), "/etc/hostname"), None);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(repo.path().join("inside.ts"), repo.path().join("link.ts")).unwrap();
        assert_eq!(read_checkout_file(repo.path(), "link.ts"), None);
    }
}
