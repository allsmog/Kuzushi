use super::recount_hunk_headers;
use std::process::{Command, Stdio};

/// Shape of the diff Claude Haiku 4.5 synthesized for Juice Shop's hardcoded
/// HMAC secret: a correct body under a header that claims 7 old lines for 5.
const JUICE_SHOP_DIFF: &str = "--- a/lib/insecurity.ts
+++ b/lib/insecurity.ts
@@ -51,7 +51,7 @@ interface IAuthenticatedUsers {
 
 export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
-export const hmac = (data: string) => crypto.createHmac('sha256', 'secret').update(data).digest('hex')
+export const hmac = (data: string) => crypto.createHmac('sha256', process.env.HMAC_SECRET || 'secret').update(data).digest('hex')
 
 export const cutOffPoisonNullByte = (str: string) => {
";

#[test]
fn miscounted_headers_are_recomputed_from_the_body() {
    let canonical = recount_hunk_headers(JUICE_SHOP_DIFF);
    assert!(
        canonical.contains("@@ -51,5 +51,5 @@ interface IAuthenticatedUsers {\n"),
        "{canonical}"
    );
}

#[test]
fn a_correct_diff_is_unchanged_and_recounting_is_idempotent() {
    let once = recount_hunk_headers(JUICE_SHOP_DIFF);
    assert_eq!(recount_hunk_headers(&once), once);
}

#[test]
fn a_bare_empty_line_inside_a_hunk_is_a_blank_context_line() {
    let diff = "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n a\n\n-b\n+c\n";
    assert_eq!(
        recount_hunk_headers(diff),
        "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n \n-b\n+c\n"
    );
}

#[test]
fn file_headers_bound_hunks_but_removed_double_dash_lines_do_not() {
    let diff = "--- a/q.sql\n+++ b/q.sql\n@@ -1,9 +1,9 @@\n--- old comment\n+-- new comment\n select 1;\n\
                --- a/r.sql\n+++ b/r.sql\n@@ -4 +4 @@ tail\n-x\n+y\n";
    let canonical = recount_hunk_headers(diff);
    assert!(canonical.contains("@@ -1,2 +1,2 @@\n--- old comment\n"), "{canonical}");
    assert!(canonical.contains("@@ -4,1 +4,1 @@ tail\n-x\n+y\n"), "{canonical}");
}

#[test]
fn no_newline_markers_and_trailing_blank_lines_are_not_counted() {
    let diff = "--- a/f\n+++ b/f\n@@ -1,5 +1,5 @@\n-a\n\\ No newline at end of file\n+b\n\n\n";
    assert_eq!(
        recount_hunk_headers(diff),
        "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+b\n"
    );
}

#[test]
fn the_recounted_juice_shop_diff_applies_with_git() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(repo.path().join("lib")).unwrap();
    let original = [
        "// preamble",
        "",
        "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')",
        "export const hmac = (data: string) => crypto.createHmac('sha256', 'secret').update(data).digest('hex')",
        "",
        "export const cutOffPoisonNullByte = (str: string) => {",
        "  return str",
        "}",
    ];
    // Pad so the hunk's recorded line 51 exists.
    let mut lines = vec!["//"; 50];
    lines.extend(original.iter().skip(1));
    std::fs::write(repo.path().join("lib/insecurity.ts"), lines.join("\n") + "\n").unwrap();
    assert!(!git_apply_check(repo.path(), JUICE_SHOP_DIFF), "raw model diff must be rejected");
    assert!(git_apply_check(repo.path(), &recount_hunk_headers(JUICE_SHOP_DIFF)));
}

fn git_apply_check(dir: &std::path::Path, diff: &str) -> bool {
    use std::io::Write;
    let mut child = Command::new("git")
        .args(["apply", "--check", "--unsafe-paths", "-"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(diff.as_bytes()).unwrap();
    child.wait().unwrap().success()
}
