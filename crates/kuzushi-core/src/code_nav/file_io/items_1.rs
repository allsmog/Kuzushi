use super::prelude::*;
use super::*;

pub const MAX_READ_BYTES: usize = 64 * 1024;

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
    let canonical = canonicalise_within(root, &input.file)
        .with_context(|| format!("read_source: path {:?}", input.file))?;
    let raw = fs::read_to_string(&canonical)
        .with_context(|| format!("read_source: could not read {}", input.file))?;

    let lines: Vec<&str> = raw.split_inclusive('\n').collect();
    let total = lines.len() as u32;

    let start = input.start_line.unwrap_or(1).max(1);
    let end = input.end_line.unwrap_or(total).min(total);
    let (start, end) = if start > end {
        (1, total)
    } else {
        (start, end)
    };

    if total == 0 {
        return Ok(ReadSourceOutput {
            file: input.file.clone(),
            start_line: 1,
            end_line: 0,
            total_lines: 0,
            contents: String::new(),
            truncated: false,
        });
    }

    let slice = &lines[(start as usize - 1)..(end as usize)];
    let mut contents = slice.concat();
    let mut truncated = false;
    if contents.len() > MAX_READ_BYTES {
        // Truncate on a UTF-8 char boundary.
        let mut cap = MAX_READ_BYTES;
        while !contents.is_char_boundary(cap) {
            cap -= 1;
        }
        contents.truncate(cap);
        contents.push_str("\n... [truncated by read_source; reissue with narrower line range]\n");
        truncated = true;
    }

    Ok(ReadSourceOutput {
        file: input.file.clone(),
        start_line: start,
        end_line: end,
        total_lines: total,
        contents,
        truncated,
    })
}
