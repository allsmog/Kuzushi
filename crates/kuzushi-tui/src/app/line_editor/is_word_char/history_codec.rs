//! Versioned history records: one JSON string per line, with a shared byte cap.
pub(super) const MAX_COMMAND_HISTORY_BYTES: usize = 1024 * 1024;
const MAGIC: &str = "# kuzushi-history-v2\n";

pub(super) fn decode(contents: &str, cap: usize) -> Result<Vec<String>, String> {
    let mut entries = match contents.strip_prefix(MAGIC) {
        Some(records) => decode_records(records)?,
        None => contents
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    entries.drain(..entries.len().saturating_sub(cap));
    Ok(entries)
}

fn decode_records(records: &str) -> Result<Vec<String>, String> {
    // A crash may leave an incomplete final record in a legacy/manual copy.
    // Never guess the contents of that record or silently skip middle damage.
    let complete = records
        .rsplit_once('\n')
        .map(|(prefix, _)| prefix)
        .unwrap_or("");
    if complete.is_empty() {
        return Ok(Vec::new());
    }
    complete
        .lines()
        .map(|record| serde_json::from_str(record).map_err(|error| error.to_string()))
        .collect()
}

pub(super) fn encode(entries: &[String], cap: usize) -> (String, usize) {
    let mut remaining = MAX_COMMAND_HISTORY_BYTES - MAGIC.len();
    let mut kept = Vec::new();
    for entry in entries.iter().rev().take(cap) {
        if let Some(record) = bounded_record(entry, remaining) {
            remaining -= record.len();
            kept.push(record);
        }
    }
    let omitted = entries.len() - kept.len();
    kept.reverse();
    (format!("{MAGIC}{}", kept.concat()), omitted)
}

fn bounded_record(entry: &str, remaining: usize) -> Option<String> {
    if entry.len() >= remaining {
        return None;
    }
    let record = format!(
        "{}\n",
        serde_json::to_string(entry).expect("string serialization")
    );
    (record.len() <= remaining).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_whitespace_unicode_and_markers_round_trip() {
        let entries = vec![
            "first\nsecond\n  ".into(),
            "\tλ 🦀 [paste 1] ".into(),
            "".into(),
        ];
        let (encoded, omitted) = encode(&entries, 200);
        assert_eq!(omitted, 0);
        assert_eq!(decode(&encoded, 200).unwrap(), entries);
    }

    #[test]
    fn legacy_lines_and_truncated_last_record_are_conservative() {
        assert_eq!(decode("one\ntwo  \n", 200).unwrap(), vec!["one", "two  "]);
        assert_eq!(
            decode(&format!("{MAGIC}\"one\"\n\"partial"), 200).unwrap(),
            vec!["one"]
        );
        assert!(decode(&format!("{MAGIC}\"one\"\ninvalid\n\"three\"\n"), 200).is_err());
    }

    #[test]
    fn writer_and_reader_share_the_same_budget() {
        let entries = vec![
            "older".into(),
            "x".repeat(MAX_COMMAND_HISTORY_BYTES),
            "recent\n".into(),
        ];
        let (encoded, omitted) = encode(&entries, 200);
        assert!(encoded.len() <= MAX_COMMAND_HISTORY_BYTES);
        assert_eq!(omitted, 1);
        assert_eq!(decode(&encoded, 200).unwrap(), vec!["older", "recent\n"]);
        let (escaped, _) = encode(&vec!["\0".repeat(200_000); 200], 200);
        assert!(escaped.len() <= MAX_COMMAND_HISTORY_BYTES);
    }
}
