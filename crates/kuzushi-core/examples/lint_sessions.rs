//! Offline session-transcript linter.
//!
//! Walks a sessions store (default `~/.kuzushi/v3/sessions`) and reports
//! per-session lint findings: repeated-message storms, long silences after
//! view changes, and slow first responses to submitted commands.
//!
//! ```text
//! cargo run -p kuzushi-core --example lint_sessions [-- <sessions-root>]
//! ```

use kuzushi_core::session_transcript::{
    lint_session_records, SessionLintFinding, SessionLintOptions, SessionRecord,
};
use std::path::{Path, PathBuf};

fn main() {
    let root = sessions_root();
    let mut files = Vec::new();
    collect_jsonl_files(&root, &mut files);
    files.sort();
    if files.is_empty() {
        println!("no session transcripts under {}", root.display());
        return;
    }
    let options = SessionLintOptions::default();
    let mut flagged = 0;
    for file in &files {
        flagged += usize::from(lint_one_session(file, &options));
    }
    println!(
        "\n{} session(s) examined, {} with findings",
        files.len(),
        flagged
    );
}

fn sessions_root() -> PathBuf {
    if let Some(argument) = std::env::args().nth(1) {
        return PathBuf::from(argument);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    kuzushi_core::session_transcript::default_sessions_root(home)
}

fn collect_jsonl_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "jsonl") {
            files.push(path);
        }
    }
}

fn lint_one_session(file: &Path, options: &SessionLintOptions) -> bool {
    let records = match read_records(file) {
        Ok(records) => records,
        Err(error) => {
            println!("{}: unreadable — {error}", file.display());
            return true;
        }
    };
    let findings = lint_session_records(&records, options);
    if findings.is_empty() {
        return false;
    }
    println!("\n{} ({} records)", file.display(), records.len());
    for finding in &findings {
        print_finding(finding);
    }
    true
}

fn read_records(file: &Path) -> std::io::Result<Vec<SessionRecord>> {
    let body = std::fs::read_to_string(file)?;
    Ok(body
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

fn print_finding(finding: &SessionLintFinding) {
    println!(
        "  [{:?}] seq {} at {}\n    {}",
        finding.kind, finding.sequence, finding.timestamp, finding.detail
    );
}
