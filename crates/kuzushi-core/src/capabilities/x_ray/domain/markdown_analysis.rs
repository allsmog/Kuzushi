use super::*;

pub(crate) fn is_likely_entry_label(value: &str) -> bool {
    let normalized = value.replace(['`', '*', '_'], "").trim().to_string();
    normalized.contains('(')
        || normalized.contains("::")
        || normalized.contains('.')
        || normalized
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
}

pub(crate) fn parse_invariant_counts(markdown: &str) -> XRayInvariantCounts {
    let global = count_prefixed_tokens(markdown, 'G');
    let integration = count_prefixed_tokens(markdown, 'I');
    let cross_chain = count_prefixed_tokens(markdown, 'X');
    let economic = count_prefixed_tokens(markdown, 'E');
    let total = global + integration + cross_chain + economic;
    XRayInvariantCounts {
        global,
        integration,
        cross_chain,
        economic,
        total: if total > 0 {
            total
        } else {
            count_invariant_headings(markdown)
        },
    }
}

pub(super) fn count_prefixed_tokens(text: &str, prefix: char) -> usize {
    let chars = text.chars().collect::<Vec<_>>();
    let mut out = BTreeSet::new();
    let mut index = 0usize;
    while index < chars.len() {
        if !chars[index].eq_ignore_ascii_case(&prefix) {
            index += 1;
            continue;
        }
        let previous_is_word = index > 0 && chars[index - 1].is_ascii_alphanumeric();
        if previous_is_word {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        if chars.get(cursor) == Some(&'-') {
            cursor += 1;
        }
        let start_digits = cursor;
        while chars
            .get(cursor)
            .is_some_and(|candidate| candidate.is_ascii_digit())
        {
            cursor += 1;
        }
        if cursor > start_digits {
            let digits = chars[start_digits..cursor].iter().collect::<String>();
            out.insert(format!("{}-{}", prefix.to_ascii_uppercase(), digits));
        }
        index = cursor.max(index + 1);
    }
    out.len()
}

pub(super) fn count_invariant_headings(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
            (3..=5).contains(&hashes) && trimmed.to_ascii_lowercase().contains("invariant")
        })
        .count()
}

pub(super) fn extract_heading_section(markdown: &str, heading: &str) -> Option<String> {
    let lines = markdown.lines().collect::<Vec<_>>();
    let heading_lower = heading.to_ascii_lowercase();
    let start = lines.iter().position(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with('#') && trimmed.to_ascii_lowercase().contains(&heading_lower)
    })?;
    let level = lines[start]
        .chars()
        .take_while(|ch| *ch == '#')
        .count()
        .max(1);
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            let count = trimmed.chars().take_while(|ch| *ch == '#').count();
            count > 0 && count <= level && trimmed.chars().nth(count) == Some(' ')
        })
        .map(|(index, _)| index)
        .unwrap_or(lines.len());
    Some(lines[start + 1..end].join("\n"))
}

pub(crate) fn repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| path.display().to_string())
}
