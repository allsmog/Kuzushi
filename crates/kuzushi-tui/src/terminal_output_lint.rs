//! Interactive code must communicate through application state. Direct
//! process output desynchronizes Ratatui's alternate-screen diff model.

use std::path::{Path, PathBuf};

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

fn output_patterns() -> [String; 10] {
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

fn is_test_only_file(relative: &str) -> bool {
    relative.ends_with("tests.rs") || relative.contains("/tests/")
}

fn is_audited_presentation_output(relative: &str, line: &str) -> bool {
    match relative {
        "app/runtime/refresh_terminal_redraw_state.rs" => {
            line.contains("terminal-output: plain-mode")
        }
        "app/effects.rs" => line.contains("terminal-output: inline fixture"),
        "app/settings/normalize_thinking_level/auth_process.rs" => {
            line.contains("terminal-output: suspended child")
        }
        _ => false,
    }
}

fn contains_output_pattern(line: &str, patterns: &[String]) -> bool {
    let compact = line
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    patterns.iter().any(|pattern| compact.contains(pattern))
}

fn file_violations(root: &Path, label: &str, path: &Path, patterns: &[String]) -> Vec<String> {
    let suffix = path
        .strip_prefix(root)
        .expect("source under root")
        .to_string_lossy()
        .replace('\\', "/");
    let relative = format!("{label}/{suffix}");
    if is_test_only_file(&relative) {
        return Vec::new();
    }
    let body = std::fs::read_to_string(path).expect("read interactive source");
    body.lines()
        .filter(|line| contains_output_pattern(line, patterns))
        .filter(|line| !is_audited_presentation_output(&relative, line))
        .map(|line| format!("{relative}: {}", line.trim()))
        .collect()
}

fn tree_violations(root: &Path, label: &str, patterns: &[String]) -> Vec<String> {
    let mut sources = Vec::new();
    rust_sources(root, &mut sources);
    sources
        .iter()
        .flat_map(|path| file_violations(root, label, path, patterns))
        .collect()
}

fn interactive_terminal_write_violations() -> Vec<String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns = output_patterns();
    let mut violations = tree_violations(&manifest.join("src/app"), "app", &patterns);
    violations.extend(tree_violations(
        &manifest.join("../kuzushi-codeindex/src"),
        "kuzushi-codeindex",
        &patterns,
    ));
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_runtime_never_writes_behind_ratatui() {
        let violations = interactive_terminal_write_violations();
        assert!(
            violations.is_empty(),
            "interactive code must route output through application state:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn terminal_write_matcher_ignores_spacing_and_catches_inherited_stdio() {
        let patterns = output_patterns();
        assert!(contains_output_pattern("eprintln ! (\"bad\")", &patterns));
        assert!(contains_output_pattern(
            ".stderr( Stdio :: inherit () )",
            &patterns
        ));
    }
}
