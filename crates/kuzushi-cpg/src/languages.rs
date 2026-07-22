//! Language keys the cpg-rs engine can build natively, plus the mapping from
//! kuzushi's language inventory names onto them.

use std::path::Path;

/// Canonical cpg-rs language keys, in the spelling `cpg_cli::make_project`
/// accepts. Kotlin/C#/PHP/Swift/bytecode are NOT here — those languages have
/// no in-process frontend and fall back to codeql/structural evidence.
const SUPPORTED: &[&str] = &[
    "c",
    "cpp",
    "go",
    "java",
    "javascript",
    "python",
    "ruby",
    "rust",
    "scala",
    "typescript",
];

pub fn supported_languages() -> &'static [&'static str] {
    SUPPORTED
}

/// Map a kuzushi inventory language name onto the cpg-rs key, or `None` when
/// the engine has no frontend for it.
pub fn canonical_language(lang: &str) -> Option<&'static str> {
    match lang.to_ascii_lowercase().as_str() {
        "c" => Some("c"),
        "cpp" | "c++" | "cxx" | "cc" => Some("cpp"),
        "go" | "golang" => Some("go"),
        "java" => Some("java"),
        "javascript" | "js" | "jsx" => Some("javascript"),
        "python" | "py" => Some("python"),
        "ruby" | "rb" => Some("ruby"),
        "rust" | "rs" => Some("rust"),
        "scala" => Some("scala"),
        "typescript" | "ts" | "tsx" => Some("typescript"),
        _ => None,
    }
}

/// Source-file extensions per canonical language, mirroring
/// `cpg_cli::make_project`'s ownership so build and staleness agree.
pub(crate) fn extensions_for(lang: &str) -> &'static [&'static str] {
    cpg_cli::make_project(lang).1
}

/// Languages present under `dir` that cpg-rs can build, ordered by source
/// file count (dominant first). Polyglot M&A checkouts get one project per
/// language; an empty result means no supported language was found.
pub fn detect_buildable_languages(dir: &Path) -> Vec<&'static str> {
    let mut counts: Vec<(usize, &'static str)> = SUPPORTED
        .iter()
        .map(|lang| (count_sources(dir, lang), *lang))
        .filter(|(count, _)| *count > 0)
        .collect();
    counts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    resolve_c_cpp_overlap(counts.into_iter().map(|(_, lang)| lang).collect())
}

/// `.h` files count toward both c and cpp; when both are detected keep only
/// the dominant one so a C repo doesn't also build a header-only cpp graph.
fn resolve_c_cpp_overlap(langs: Vec<&'static str>) -> Vec<&'static str> {
    let c_pos = langs.iter().position(|l| *l == "c");
    let cpp_pos = langs.iter().position(|l| *l == "cpp");
    match (c_pos, cpp_pos) {
        (Some(c), Some(cpp)) => {
            let drop = if c < cpp { "cpp" } else { "c" };
            langs.into_iter().filter(|l| *l != drop).collect()
        }
        _ => langs,
    }
}

fn count_sources(dir: &Path, lang: &str) -> usize {
    let exts = extensions_for(lang);
    let excludes = cpg_cli::workspace::excludes_for(lang);
    let mut count = 0usize;
    walk_sources(dir, exts, excludes, &mut |_| count += 1);
    count
}

/// Minimal recursive source walk honouring the engine's per-language exclude
/// substrings. Shared by language detection and staleness checks.
pub(crate) fn walk_sources(
    dir: &Path,
    exts: &[&str],
    excludes: &[&str],
    visit: &mut impl FnMut(&Path),
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_excluded(&path, excludes) {
            continue;
        }
        if path.is_dir() {
            walk_sources(&path, exts, excludes, visit);
        } else if has_extension(&path, exts) {
            visit(&path);
        }
    }
}

fn is_excluded(path: &Path, excludes: &[&str]) -> bool {
    let text = path.to_string_lossy();
    excludes.iter().any(|pattern| text.contains(pattern)) || text.contains("/.git/")
}

fn has_extension(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| exts.contains(&ext))
}
