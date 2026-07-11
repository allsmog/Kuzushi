use super::*;

pub const MAX_READ_BYTES: usize = 64 * 1024;
const MAX_SOURCE_FILE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSourceInput {
    pub file: String,
    #[serde(default)]
    pub start_line: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSourceOutput {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub total_lines: u32,
    pub contents: String,
    pub truncated: bool,
}

pub fn read_source(root: &Path, input: &ReadSourceInput) -> Result<ReadSourceOutput> {
    let raw = read_source_file(root, &input.file)?;
    let lines: Vec<&str> = raw.split_inclusive('\n').collect();
    let total = lines.len() as u32;
    if total == 0 {
        return Ok(empty_source_output(input));
    }
    let (start, end) = selected_line_range(input, total);
    let (contents, truncated) = selected_source_contents(&lines, start, end);
    Ok(ReadSourceOutput {
        file: input.file.clone(),
        start_line: start,
        end_line: end,
        total_lines: total,
        contents,
        truncated,
    })
}

fn read_source_file(root: &Path, file: &str) -> Result<String> {
    let canonical =
        canonicalise_within(root, file).with_context(|| format!("read_source: path {file:?}"))?;
    crate::bounded_file::read_utf8_text(&canonical, MAX_SOURCE_FILE_BYTES)
        .map_err(|error| anyhow::anyhow!("read_source: could not read {file}: {error}"))
}

fn empty_source_output(input: &ReadSourceInput) -> ReadSourceOutput {
    ReadSourceOutput {
        file: input.file.clone(),
        start_line: 1,
        end_line: 0,
        total_lines: 0,
        contents: String::new(),
        truncated: false,
    }
}

fn selected_line_range(input: &ReadSourceInput, total: u32) -> (u32, u32) {
    let start = input.start_line.unwrap_or(1).max(1);
    let end = input.end_line.unwrap_or(total).min(total);
    (start <= end).then_some((start, end)).unwrap_or((1, total))
}

fn selected_source_contents(lines: &[&str], start: u32, end: u32) -> (String, bool) {
    let contents = lines[(start as usize - 1)..(end as usize)].concat();
    truncate_source_contents(contents)
}

fn truncate_source_contents(mut contents: String) -> (String, bool) {
    if contents.len() <= MAX_READ_BYTES {
        return (contents, false);
    }
    let mut cap = MAX_READ_BYTES;
    while !contents.is_char_boundary(cap) {
        cap -= 1;
    }
    contents.truncate(cap);
    contents.push_str("\n... [truncated by read_source; reissue with narrower line range]\n");
    (contents, true)
}
