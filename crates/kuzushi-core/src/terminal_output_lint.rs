//! Ratchet reusable core code away from process stdout/stderr. Presentation
//! belongs to CLI/TUI boundaries; core reports through runtime diagnostics.

use std::path::{Path, PathBuf};

fn print_macro_patterns() -> [String; 10] {
    [
        format!("{}!(", "println"),
        format!("{}!(", "eprintln"),
        format!("{}!(", "print"),
        format!("{}!(", "eprint"),
        format!("{}!(io::stderr()", "write"),
        format!("{}!(io::stderr()", "writeln"),
        format!("{}!(std::io::stderr()", "write"),
        format!("{}!(std::io::stderr()", "writeln"),
        format!("{}!(", "dbg"),
        format!("{}::inherit()", "Stdio"),
    ]
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn is_test_only_file(relative: &str) -> bool {
    relative.ends_with("tests.rs")
        || relative.contains("/tests/")
        || relative == "run_lifecycle/persistence/writer_characterization.rs"
}

fn is_audited_inline_test_print(relative: &str, line: &str) -> bool {
    relative == "capabilities/threat_intel/application/regression_gate.rs"
        && line.contains("skipping live gate test: git binary not on PATH")
}

fn contains_print_pattern(line: &str, patterns: &[String]) -> bool {
    let compact = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    patterns.iter().any(|pattern| compact.contains(pattern))
}

fn file_violations(src: &Path, path: &Path, patterns: &[String]) -> Vec<String> {
    let relative = path
        .strip_prefix(src)
        .expect("source under src")
        .to_string_lossy()
        .replace('\\', "/");
    if is_test_only_file(&relative) || relative == "terminal_output_lint.rs" {
        return Vec::new();
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|line| contains_print_pattern(line, patterns))
        .filter(|line| !is_audited_inline_test_print(&relative, line))
        .map(|line| format!("{relative}: {}", line.trim()))
        .collect()
}

fn reusable_core_terminal_write_violations() -> Vec<String> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources(&src, &mut sources);
    let patterns = print_macro_patterns();
    sources
        .iter()
        .flat_map(|path| file_violations(&src, path, &patterns))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reusable_core_has_no_direct_terminal_writes() {
        let violations = reusable_core_terminal_write_violations();
        assert!(
            violations.is_empty(),
            "reusable core code must report through runtime diagnostics, not stdout/stderr:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn terminal_write_matcher_ignores_macro_spacing() {
        let patterns = print_macro_patterns();
        assert!(contains_print_pattern("eprintln ! (\"bad\")", &patterns));
        assert!(contains_print_pattern(
            "writeln ! ( std :: io :: stderr (), \"bad\")",
            &patterns
        ));
    }
}
