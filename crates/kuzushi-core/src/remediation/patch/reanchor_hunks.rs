//! Re-anchor model-written hunks against the source they patch.
//!
//! Models copy the changed lines faithfully but often send zero or one-sided
//! context (`@@ -21,1 +21,1 @@`). `git apply` treats a hunk with no trailing
//! context as anchored to the end of the file, so a correct mid-file edit is
//! rejected as "patch does not apply". Synthesis runs in a checkout of the
//! exact source commit, so each hunk's old side can be located there and
//! re-emitted with real surrounding context and exact line numbers.
//!
//! Only an unambiguous rewrite is made: every hunk of a file must match its
//! old block exactly once, in order, without overlap. Anything else (a new or
//! deleted file, a no-newline marker, an unmatched or repeated block) leaves
//! that file's section byte-for-byte as the model wrote it, so validation
//! still fails honestly instead of patching a guessed location.

use std::path::Path;

const CONTEXT_LINES: usize = 3;

/// Re-anchor `diff` against files under `checkout`.
pub(crate) fn reanchor_hunks_in_checkout(checkout: &Path, diff: &str) -> String {
    reanchor_hunks(diff, &|path| read_checkout_file(checkout, path))
}

/// The same ceiling `apply_reviewed_patch` enforces on a touched file.
const MAX_REANCHOR_SOURCE_BYTES: usize = 64 * 1024 * 1024;

/// Read a checkout file named by the model's diff: confined beneath the
/// checkout, never through a symlink, and only when it fits the ceiling.
fn read_checkout_file(checkout: &Path, relative: &str) -> Option<String> {
    let relative = Path::new(relative);
    let confined = relative.is_relative()
        && relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)));
    confined
        .then(|| {
            crate::bounded_file::read_utf8_text_within(
                checkout,
                &checkout.join(relative),
                MAX_REANCHOR_SOURCE_BYTES,
            )
            .ok()
        })
        .flatten()
}

pub(crate) fn reanchor_hunks(diff: &str, source: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = Vec::new();
    for section in split_sections(diff) {
        out.extend(reanchored_section(&section, source).unwrap_or(section.lines));
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// One `--- a/… +++ b/…` file section (or the preamble before the first).
struct Section {
    lines: Vec<String>,
}

fn split_sections(diff: &str) -> Vec<Section> {
    let lines = diff.lines().collect::<Vec<_>>();
    let mut sections = vec![Section { lines: Vec::new() }];
    for (index, line) in lines.iter().enumerate() {
        let current = sections.last().expect("at least the preamble");
        if starts_section(current, &lines, index) {
            sections.push(Section { lines: Vec::new() });
        }
        let current = sections.last_mut().expect("at least the preamble");
        current.lines.push((*line).to_string());
    }
    sections
}

/// A `diff --git` line opens a section; so does a `--- `/`+++ ` pair unless
/// it completes the `diff --git` header already open.
fn starts_section(current: &Section, lines: &[&str], index: usize) -> bool {
    if lines[index].starts_with("diff --git ") {
        return true;
    }
    let file_header = lines[index].starts_with("--- ")
        && lines
            .get(index + 1)
            .is_some_and(|next| next.starts_with("+++ "));
    file_header && !open_git_header(current)
}

fn open_git_header(section: &Section) -> bool {
    section
        .lines
        .first()
        .is_some_and(|line| line.starts_with("diff --git "))
        && !section.lines.iter().any(|line| line.starts_with("--- "))
}

struct Hunk {
    section: String,
    body: Vec<String>,
}

impl Hunk {
    fn old_side(&self) -> Vec<&str> {
        self.side(b'-')
    }

    fn new_len(&self) -> usize {
        self.side(b'+').len()
    }

    /// Context lines plus the lines only one side has (`-` old, `+` new).
    fn side(&self, changed: u8) -> Vec<&str> {
        self.body
            .iter()
            .filter(|line| [b' ', changed].contains(&line.as_bytes()[0]))
            .map(|line| &line[1..])
            .collect()
    }
}

fn reanchored_section(section: &Section, source: &dyn Fn(&str) -> Option<String>) -> Option<Vec<String>> {
    let hunk_start = section.lines.iter().position(|line| line.starts_with("@@"))?;
    let header = &section.lines[..hunk_start];
    let content = source(&old_path(header)?)?;
    let file = content.lines().collect::<Vec<_>>();
    let hunks = parse_hunks(&section.lines[hunk_start..])?;
    let starts = locate_hunks(&hunks, &file)?;
    let mut out = header.to_vec();
    out.extend(render_hunks(&hunks, &starts, &file));
    Some(out)
}

/// The old path of a modification; new files, deletions, and renames whose
/// sides differ are left alone.
fn old_path(header: &[String]) -> Option<String> {
    let old = header.iter().find_map(|line| line.strip_prefix("--- a/"))?;
    let new = header.iter().find_map(|line| line.strip_prefix("+++ b/"))?;
    (old == new).then(|| old.split('\t').next().unwrap_or(old).to_string())
}

fn parse_hunks(lines: &[String]) -> Option<Vec<Hunk>> {
    let mut hunks: Vec<Hunk> = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("@@") {
            hunks.push(Hunk {
                section: rest.split_once(" @@").map_or("", |(_, tail)| tail).to_string(),
                body: Vec::new(),
            });
            continue;
        }
        let hunk = hunks.last_mut()?;
        plain_body_line(line)?;
        hunk.body.push(line.clone());
    }
    hunks.iter().all(|hunk| !hunk.old_side().is_empty()).then_some(hunks)
}

/// Context, removal, or addition; a `\ No newline` marker is not re-anchored.
fn plain_body_line(line: &str) -> Option<()> {
    matches!(line.as_bytes().first(), Some(b' ' | b'+' | b'-')).then_some(())
}

/// Zero-based start of each hunk's old block: unique, ordered, disjoint.
fn locate_hunks(hunks: &[Hunk], file: &[&str]) -> Option<Vec<usize>> {
    let mut starts = Vec::with_capacity(hunks.len());
    let mut floor = 0;
    for hunk in hunks {
        let old = hunk.old_side();
        let start = unique_match(file, &old)?;
        (start >= floor).then_some(())?;
        floor = start + old.len();
        starts.push(start);
    }
    Some(starts)
}

fn unique_match(file: &[&str], block: &[&str]) -> Option<usize> {
    let mut matches = (0..=file.len().checked_sub(block.len())?)
        .filter(|start| file[*start..*start + block.len()] == *block);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn render_hunks(hunks: &[Hunk], starts: &[usize], file: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset: isize = 0;
    let mut consumed = 0;
    for (index, hunk) in hunks.iter().enumerate() {
        let next_start = starts.get(index + 1).copied().unwrap_or(file.len());
        let window = ContextWindow::new(starts[index], hunk.old_side().len(), consumed, next_start);
        consumed = window.end + window.after;
        out.extend(render_hunk(hunk, &window, file, offset));
        offset += hunk.new_len() as isize - hunk.old_side().len() as isize;
    }
    out
}

/// Context borrowed from the file. Leading context starts after whatever the
/// previous hunk already showed, so neighbouring hunks never repeat a line.
struct ContextWindow {
    start: usize,
    end: usize,
    before: usize,
    after: usize,
}

impl ContextWindow {
    fn new(start: usize, old_len: usize, consumed: usize, next_start: usize) -> Self {
        let end = start + old_len;
        Self {
            start,
            end,
            before: CONTEXT_LINES.min(start - consumed),
            after: CONTEXT_LINES.min(next_start - end),
        }
    }
}

fn render_hunk(hunk: &Hunk, window: &ContextWindow, file: &[&str], offset: isize) -> Vec<String> {
    let before = &file[window.start - window.before..window.start];
    let after = &file[window.end..window.end + window.after];
    let context = window.before + window.after;
    let old_count = hunk.old_side().len() + context;
    let new_count = hunk.new_len() + context;
    let old_start = window.start - window.before + 1;
    let new_start = (old_start as isize + offset).max(1);
    let mut out = vec![format!(
        "@@ -{old_start},{old_count} +{new_start},{new_count} @@{}",
        hunk.section
    )];
    out.extend(before.iter().map(|line| format!(" {line}")));
    out.extend(hunk.body.iter().cloned());
    out.extend(after.iter().map(|line| format!(" {line}")));
    out
}

#[cfg(test)]
mod tests;
