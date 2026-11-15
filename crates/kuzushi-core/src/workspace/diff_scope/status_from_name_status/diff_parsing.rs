use super::*;

pub(in crate::workspace::diff_scope) fn status_from_name_status(code: &str) -> DiffFileStatus {
    match code.chars().next().unwrap_or(' ') {
        'A' => DiffFileStatus::Added,
        'M' => DiffFileStatus::Modified,
        'D' => DiffFileStatus::Deleted,
        'R' => DiffFileStatus::Renamed,
        'C' => DiffFileStatus::Copied,
        'T' => DiffFileStatus::TypeChanged,
        _ => DiffFileStatus::Unknown,
    }
}

/// The line span one hunk header declares.
#[derive(Clone, Copy)]
pub(in crate::workspace::diff_scope) struct HunkSpan {
    old_start: u32,
    old_count: u32,
    new_start: u32,
    new_count: u32,
}

/// Where in one file's patch the reader currently stands.
///
/// `---`/`+++` name a file only in the header git writes between a
/// `diff --git` line and that file's first hunk. They are not anchors that
/// hold anywhere in the patch: with `--unified=0` a removed source line
/// beginning `-- ` renders as `--- `, so a reader that accepts the prefix
/// inside a hunk body re-points itself at whatever that line of source
/// happened to spell and attributes the next hunk's ranges to it.
#[derive(Default)]
struct DiffCursor {
    old_path: Option<String>,
    new_path: Option<String>,
    in_header: bool,
}

impl DiffCursor {
    /// The hunk `line` opens, after folding a file-header line into the paths.
    fn read(&mut self, line: &str) -> Result<Option<HunkSpan>> {
        if line.starts_with("diff --git ") {
            *self = Self {
                in_header: true,
                ..Self::default()
            };
            return Ok(None);
        }
        if self.in_header && self.read_header_path(line)? {
            return Ok(None);
        }
        if !line.starts_with("@@ ") {
            return Ok(None);
        }
        self.in_header = false;
        Ok(parse_hunk_header(line))
    }

    /// Whether `line` was one of the two header lines naming the file.
    fn read_header_path(&mut self, line: &str) -> Result<bool> {
        if let Some(raw) = line.strip_prefix("--- ") {
            self.old_path = parse_diff_path(raw)?;
            return Ok(true);
        }
        if let Some(raw) = line.strip_prefix("+++ ") {
            self.new_path = parse_diff_path(raw)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The path a hunk's ranges belong to: the post-image name, or the
    /// pre-image name when the file is gone from the post-image.
    fn key(&self) -> Option<&String> {
        self.new_path
            .as_ref()
            .or(self.old_path.as_ref())
            .filter(|path| !path.is_empty())
    }
}

pub(in crate::workspace::diff_scope) fn parse_unified_diff_ranges(
    output: &str,
    files: &mut BTreeMap<String, ChangedFile>,
) -> Result<()> {
    let mut cursor = DiffCursor::default();
    for line in output.lines() {
        if let Some(span) = cursor.read(line)? {
            record_hunk_span(files, &cursor, span);
        }
    }
    for file in files.values_mut() {
        sort_ranges(&mut file.changed_ranges);
        sort_ranges(&mut file.deleted_ranges);
    }
    Ok(())
}

fn record_hunk_span(
    files: &mut BTreeMap<String, ChangedFile>,
    cursor: &DiffCursor,
    span: HunkSpan,
) {
    let Some(key) = cursor.key().cloned() else {
        return;
    };
    let file = files.entry(key.clone()).or_insert_with(|| ChangedFile {
        path: key,
        previous_path: cursor.old_path.clone(),
        status: DiffFileStatus::Unknown,
        changed_ranges: Vec::new(),
        deleted_ranges: Vec::new(),
    });
    push_range(
        &mut file.changed_ranges,
        span.new_start,
        span.new_count,
        if span.old_count == 0 {
            DiffRangeKind::Added
        } else {
            DiffRangeKind::Modified
        },
    );
    push_range(
        &mut file.deleted_ranges,
        span.old_start,
        span.old_count,
        if span.new_count == 0 {
            DiffRangeKind::Deleted
        } else {
            DiffRangeKind::Modified
        },
    );
}

fn push_range(ranges: &mut Vec<ChangedLineRange>, start: u32, count: u32, kind: DiffRangeKind) {
    if count == 0 {
        return;
    }
    ranges.push(ChangedLineRange {
        start_line: start,
        end_line: start + count - 1,
        kind,
    });
}

fn sort_ranges(ranges: &mut [ChangedLineRange]) {
    ranges.sort_by_key(|range| (range.start_line, range.end_line, range.kind));
}

/// The repository path a `--- `/`+++ ` header names, or `None` for
/// `/dev/null`.
///
/// Git quotes the whole prefixed name when it holds a byte it must not emit
/// literally, so `src/café.rs` arrives as `"b/src/caf\303\251.rs"` and the
/// `b/` has to come off after the quoting is decoded, not before. A name
/// ending in whitespace is followed by a tab terminator — git writes one for a
/// quoted name too — so exactly that tab comes off and nothing else: trimming
/// the line would eat the name's own trailing space.
pub(in crate::workspace::diff_scope) fn parse_diff_path(raw: &str) -> Result<Option<String>> {
    let raw = raw.strip_suffix('\t').unwrap_or(raw);
    if raw == "/dev/null" {
        return Ok(None);
    }
    let name = match crate::git_quoted_path::take_quoted_path(raw)? {
        Some((decoded, _)) => decoded,
        None => raw.to_string(),
    };
    Ok(Some(strip_diff_prefix(&name)))
}

fn strip_diff_prefix(name: &str) -> String {
    name.strip_prefix("a/")
        .or_else(|| name.strip_prefix("b/"))
        .unwrap_or(name)
        .to_string()
}

pub(in crate::workspace::diff_scope) fn parse_hunk_header(line: &str) -> Option<HunkSpan> {
    let header = line.strip_prefix("@@ ")?.split(" @@").next()?;
    let mut parts = header.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (old_start, old_count) = parse_hunk_range(old)?;
    let (new_start, new_count) = parse_hunk_range(new)?;
    Some(HunkSpan {
        old_start,
        old_count,
        new_start,
        new_count,
    })
}

pub(in crate::workspace::diff_scope) fn parse_hunk_range(raw: &str) -> Option<(u32, u32)> {
    if let Some((start, count)) = raw.split_once(',') {
        Some((start.parse().ok()?, count.parse().ok()?))
    } else {
        Some((raw.parse().ok()?, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_header_name_decodes_before_its_prefix_comes_off() {
        assert_eq!(
            parse_diff_path(r#""b/src/caf\303\251.rs""#).unwrap(),
            Some("src/café.rs".to_string())
        );
        assert_eq!(
            parse_diff_path(r#""a/has\"quote.rs""#).unwrap(),
            Some("has\"quote.rs".to_string())
        );
    }

    #[test]
    fn only_gits_tab_terminator_comes_off_a_name_ending_in_a_space() {
        assert_eq!(
            parse_diff_path("b/trail \t").unwrap(),
            Some("trail ".to_string())
        );
        assert_eq!(
            parse_diff_path("b/with space.rs").unwrap(),
            Some("with space.rs".to_string())
        );
    }

    #[test]
    fn dev_null_names_no_file() {
        assert_eq!(parse_diff_path("/dev/null").unwrap(), None);
    }

    #[test]
    fn a_header_shaped_line_inside_a_hunk_body_is_not_a_file_header() {
        // `--unified=0` renders a removed `-- …` source line as `--- …` and an
        // added `++ …` line as `+++ …`. Both appear here, and the second
        // hunk's ranges still belong to the file the real header named.
        let diff = concat!(
            "diff --git a/real.sql b/real.sql\n",
            "--- a/real.sql\n",
            "+++ b/real.sql\n",
            "@@ -1 +1 @@\n",
            "--- \"unterminated comment\n",
            "+++ a/decoy.sql\n",
            "@@ -5,0 +6,2 @@\n",
            "+one\n",
            "+two\n",
        );
        let mut files = BTreeMap::new();

        parse_unified_diff_ranges(diff, &mut files).unwrap();

        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), ["real.sql"]);
        assert_eq!(
            files["real.sql"]
                .changed_ranges
                .iter()
                .map(|range| (range.start_line, range.end_line))
                .collect::<Vec<_>>(),
            vec![(1, 1), (6, 7)]
        );
    }

    #[test]
    fn ranges_land_on_the_name_the_header_declared() {
        let diff = concat!(
            "diff --git \"a/caf\\303\\251.rs\" \"b/caf\\303\\251.rs\"\n",
            "--- \"a/caf\\303\\251.rs\"\n",
            "+++ \"b/caf\\303\\251.rs\"\n",
            "@@ -2 +2 @@\n",
            "-old\n",
            "+new\n",
        );
        let mut files = BTreeMap::new();

        parse_unified_diff_ranges(diff, &mut files).unwrap();

        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), ["café.rs"]);
        assert_eq!(files["café.rs"].changed_ranges[0].kind, DiffRangeKind::Modified);
        assert_eq!(files["café.rs"].deleted_ranges[0].kind, DiffRangeKind::Modified);
    }

    #[test]
    fn a_deleted_files_ranges_belong_to_the_name_it_had() {
        let diff = concat!(
            "diff --git \"a/caf\\303\\251.rs\" \"b/caf\\303\\251.rs\"\n",
            "deleted file mode 100644\n",
            "--- \"a/caf\\303\\251.rs\"\n",
            "+++ /dev/null\n",
            "@@ -1,2 +0,0 @@\n",
            "-one\n",
            "-two\n",
        );
        let mut files = BTreeMap::new();

        parse_unified_diff_ranges(diff, &mut files).unwrap();

        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), ["café.rs"]);
        assert!(files["café.rs"].changed_ranges.is_empty());
        assert_eq!(
            files["café.rs"].deleted_ranges[0].kind,
            DiffRangeKind::Deleted
        );
    }

    #[test]
    fn a_header_git_could_not_have_written_is_refused() {
        let diff = concat!(
            "diff --git a/x.rs b/x.rs\n",
            "--- a/x.rs\n",
            "+++ \"b/unterminated.rs\n",
            "@@ -1 +1 @@\n",
        );
        let mut files = BTreeMap::new();

        let error = parse_unified_diff_ranges(diff, &mut files)
            .unwrap_err()
            .to_string();

        assert!(error.contains("closing quote"), "{error}");
    }
}
