use super::model::{Candidate, CodeLine, FileExcerpt};
use anyhow::Result;

pub(super) fn excerpt(
    candidate: &Candidate,
    raw: &str,
    quota: usize,
) -> Result<Option<FileExcerpt>> {
    let projected = crate::workspace::rust_test_source::surface_source(&candidate.language, raw);
    let lines: Vec<_> = projected.lines().collect();
    let mut file = empty_excerpt(candidate, raw, &lines);
    let Some(budget) = quota.checked_sub(serde_json::to_vec(&file)?.len()) else {
        return Ok(None);
    };
    file.lines = selected_lines(candidate, &lines, budget)?;
    file.omitted_lines = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .count()
        .saturating_sub(file.lines.len());
    Ok(Some(file))
}

fn empty_excerpt(candidate: &Candidate, raw: &str, projected: &[&str]) -> FileExcerpt {
    let excluded_test_lines = raw
        .lines()
        .zip(projected)
        .filter(|(raw, projected)| !raw.trim().is_empty() && projected.trim().is_empty())
        .count();
    FileExcerpt {
        path: candidate.citation_path.clone(),
        language: candidate.language.clone(),
        file_sha256: crate::options::prompt_content_sha256(raw),
        projection: projection_name(&candidate.language),
        total_lines: projected.len(),
        excluded_test_lines,
        omitted_lines: projected.len(),
        lines: Vec::new(),
    }
}

fn projection_name(language: &str) -> &'static str {
    if language == "Rust" {
        crate::workspace::rust_surface_policy::RUST_SURFACE_POLICY
    } else {
        "original-source"
    }
}

fn selected_lines(candidate: &Candidate, lines: &[&str], budget: usize) -> Result<Vec<CodeLine>> {
    let mut remaining = budget;
    let mut selected = Vec::new();
    let minimum = serde_json::to_vec(&CodeLine {
        reference: format!("{}:1", candidate.citation_path),
        text: "x".to_string(),
    })?
    .len()
        + 1;
    for index in line_priority(lines, &candidate.anchors) {
        if remaining < minimum {
            break;
        }
        if let Some(line) = take_line(
            &candidate.citation_path,
            index,
            lines[index],
            &mut remaining,
        )? {
            selected.push((index, line));
        }
    }
    selected.sort_by_key(|(index, _)| *index);
    Ok(selected.into_iter().map(|(_, line)| line).collect())
}

fn take_line(
    path: &str,
    index: usize,
    text: &str,
    remaining: &mut usize,
) -> Result<Option<CodeLine>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let line = CodeLine {
        reference: format!("{path}:{}", index + 1),
        text: text.to_string(),
    };
    let bytes = serde_json::to_vec(&line)?.len() + 1;
    if bytes > *remaining {
        return Ok(None);
    }
    *remaining -= bytes;
    Ok(Some(line))
}

fn line_priority(lines: &[&str], anchors: &[usize]) -> Vec<usize> {
    let anchors = normalized_anchors(lines.len(), anchors);
    let mut ordered: Vec<_> = (0..lines.len())
        .filter(|index| !lines[*index].trim().is_empty())
        .collect();
    ordered.sort_by_cached_key(|index| (nearest_anchor(*index, &anchors), *index));
    ordered
}

fn normalized_anchors(total: usize, anchors: &[usize]) -> Vec<usize> {
    let mut anchors: Vec<_> = anchors
        .iter()
        .copied()
        .filter(|line| *line < total)
        .collect();
    if anchors.is_empty() {
        anchors.push(0);
    }
    anchors.sort_unstable();
    anchors.dedup();
    anchors
}

fn nearest_anchor(index: usize, anchors: &[usize]) -> usize {
    anchors
        .iter()
        .map(|anchor| anchor.abs_diff(index))
        .min()
        .unwrap_or(index)
}
