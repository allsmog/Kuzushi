//! Canonicalize the hunk headers of a model-synthesized unified diff.
//!
//! Models reliably write the right hunk *body* but routinely miscount the
//! `@@ -a,b +c,d @@` line lengths, and they often emit a bare empty line for a
//! blank context line. `git apply` rejects both as a "corrupt patch" even when
//! every changed line is correct. The body is the source of truth, so each
//! header's counts are recomputed from it once, at synthesis, and every later
//! stage (validation, review, diff hash, apply, re-verify) sees one canonical
//! diff. Anything that is not a hunk is passed through untouched.

pub(crate) fn recount_hunk_headers(diff: &str) -> String {
    let lines = diff.lines().collect::<Vec<_>>();
    let mut out = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        index = match HunkHeader::parse(lines[index]) {
            Some(header) => push_recounted_hunk(&lines, index, &header, &mut out),
            None => {
                out.push(lines[index].to_string());
                index + 1
            }
        };
    }
    let mut canonical = out.join("\n").trim_end_matches('\n').to_string();
    canonical.push('\n');
    canonical
}

struct HunkHeader<'a> {
    old_start: &'a str,
    new_start: &'a str,
    section: &'a str,
}

impl<'a> HunkHeader<'a> {
    /// `@@ -a[,b] +c[,d] @@[ section]` — counts are ignored, starts kept.
    fn parse(line: &'a str) -> Option<Self> {
        let ranges = line.strip_prefix("@@ -")?;
        let (ranges, section) = ranges.split_once(" @@")?;
        let (old, new) = ranges.split_once(" +")?;
        Some(Self {
            old_start: range_start(old)?,
            new_start: range_start(new)?,
            section,
        })
    }
}

fn range_start(range: &str) -> Option<&str> {
    let start = range.split(',').next()?;
    start.bytes().all(|byte| byte.is_ascii_digit()).then_some(start)
}

fn push_recounted_hunk(
    lines: &[&str],
    header_index: usize,
    header: &HunkHeader<'_>,
    out: &mut Vec<String>,
) -> usize {
    let end = hunk_body_end(lines, header_index + 1);
    let body = lines[header_index + 1..end]
        .iter()
        .map(|line| canonical_body_line(line))
        .collect::<Vec<_>>();
    let (old_count, new_count) = body_counts(&body);
    out.push(format!(
        "@@ -{},{old_count} +{},{new_count} @@{}",
        header.old_start, header.new_start, header.section
    ));
    out.extend(body);
    end
}

/// The hunk ends at the next hunk or file header, at a line no hunk can
/// contain, or before trailing blank lines at the end of the diff.
fn hunk_body_end(lines: &[&str], start: usize) -> usize {
    let mut end = start;
    while end < lines.len() && is_hunk_body_line(lines, end) {
        end += 1;
    }
    while end > start && lines[end - 1].is_empty() {
        end -= 1;
    }
    end
}

fn is_hunk_body_line(lines: &[&str], index: usize) -> bool {
    let line = lines[index];
    if starts_file_header(lines, index) || line.starts_with("diff --git ") {
        return false;
    }
    line.is_empty() || matches!(line.as_bytes()[0], b' ' | b'+' | b'-' | b'\\')
}

fn starts_file_header(lines: &[&str], index: usize) -> bool {
    lines[index].starts_with("--- ")
        && lines
            .get(index + 1)
            .is_some_and(|next| next.starts_with("+++ "))
}

/// A bare empty line inside a hunk is a blank context line with its leading
/// space dropped.
fn canonical_body_line(line: &str) -> String {
    if line.is_empty() {
        " ".to_string()
    } else {
        line.to_string()
    }
}

fn body_counts(body: &[String]) -> (usize, usize) {
    body.iter().fold((0, 0), |(old, new), line| match line.as_bytes()[0] {
        b' ' => (old + 1, new + 1),
        b'-' => (old + 1, new),
        b'+' => (old, new + 1),
        _ => (old, new),
    })
}

#[cfg(test)]
mod tests;
