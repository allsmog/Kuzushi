//! THREAT_MODEL.md projection for the PoC: render (via the real core
//! renderer), section-aware diff, and compiling operator edits of the
//! markdown back into a JSON merge patch for the existing operator-edit path
//! (`apply_threat_model_patch_revision`).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::{json, Map, Value};

pub fn render(document: &Value, system_name: &str, target: &str) -> String {
    kuzushi_core::capabilities::render_schema_markdown(document, system_name, target)
}

// ───────────────────────────── sections ─────────────────────────────

pub struct Section {
    pub heading: String,
    pub body: Vec<String>,
}

/// Split on `## ` headings; the `# Threat Model:` title is its own section.
pub fn sections(markdown: &str) -> Vec<Section> {
    let mut out: Vec<Section> = Vec::new();
    for line in markdown.lines() {
        if line.starts_with("# ") || line.starts_with("## ") {
            out.push(Section { heading: line.to_string(), body: Vec::new() });
        } else if let Some(section) = out.last_mut() {
            section.body.push(line.to_string());
        } else {
            out.push(Section { heading: String::new(), body: vec![line.to_string()] });
        }
    }
    for section in &mut out {
        while section.body.last().is_some_and(|l| l.trim().is_empty()) {
            section.body.pop();
        }
        while section.body.first().is_some_and(|l| l.trim().is_empty()) {
            section.body.remove(0);
        }
    }
    out
}

// ─────────────────────────────── diff ───────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Same,
    Add,
    Del,
}

/// Plain LCS line diff; sections are small enough for O(n·m).
fn line_diff(a: &[String], b: &[String]) -> Vec<(Op, String)> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] { lcs[i + 1][j + 1] + 1 } else { lcs[i + 1][j].max(lcs[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            out.push((Op::Same, a[i].clone()));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push((Op::Del, a[i].clone()));
            i += 1;
        } else {
            out.push((Op::Add, b[j].clone()));
            j += 1;
        }
    }
    out
}

fn is_table_scaffold(line: &str) -> bool {
    line.starts_with("|---") || line.starts_with("| id |") || line.starts_with("| asset |")
        || line.starts_with("| entry_point |") || line.starts_with("| threat |")
        || line.starts_with("| mitigation |")
}

/// THREAT_MODEL.md diff grouped by section: unchanged sections collapse to
/// one line; changed sections show +/- rows with their table header kept for
/// orientation and long unchanged runs folded.
pub fn section_diff_lines(from_md: &str, to_md: &str) -> Vec<Line<'static>> {
    let (from, to) = (sections(from_md), sections(to_md));
    let mut lines = Vec::new();
    let mut unchanged = Vec::new();
    for target in &to {
        let base = from.iter().find(|s| s.heading == target.heading);
        let empty = Vec::new();
        let base_body = base.map(|s| &s.body).unwrap_or(&empty);
        if base.is_some() && *base_body == target.body {
            unchanged.push(short_heading(&target.heading));
            continue;
        }
        lines.push(Line::raw(""));
        let tag = if base.is_none() { "  (new section)" } else { "" };
        lines.push(Line::from(vec![
            Span::styled(target.heading.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(tag, Style::default().fg(Color::Yellow)),
        ]));
        lines.extend(section_change_lines(base_body, &target.body));
    }
    for gone in from.iter().filter(|s| !to.iter().any(|t| t.heading == s.heading)) {
        lines.push(Line::styled(format!("{}  (section removed)", gone.heading), Style::default().fg(Color::Red)));
    }
    if !unchanged.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(format!("unchanged: {}", unchanged.join(" · ")), Style::default().fg(Color::DarkGray)));
    }
    lines
}

fn short_heading(heading: &str) -> String {
    heading.trim_start_matches('#').trim().to_string()
}

/// Table sections diff as rows keyed by their first cell: a row present on
/// both sides becomes one `~ key` entry listing only the changed columns.
fn section_change_lines(base: &[String], target: &[String]) -> Vec<Line<'static>> {
    let Some(header) = target.iter().chain(base).find(|l| l.starts_with('|')).map(|l| split_row(l)) else {
        return fold_same_runs(line_diff(base, target));
    };
    let ops = line_diff(base, target);
    let is_row = |l: &str| l.starts_with('|') && !is_table_scaffold(l);
    let removed: Vec<Vec<String>> = ops.iter().filter(|(o, l)| *o == Op::Del && is_row(l)).map(|(_, l)| split_row(l)).collect();
    let added: Vec<Vec<String>> = ops.iter().filter(|(o, l)| *o == Op::Add && is_row(l)).map(|(_, l)| split_row(l)).collect();
    let key = |row: &Vec<String>| row.first().cloned().unwrap_or_default();
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let yellow = Style::default().fg(Color::Yellow);
    let muted = Style::default().fg(Color::DarkGray);
    let mut out = Vec::new();
    for row in &added {
        match removed.iter().find(|r| key(r) == key(row)) {
            Some(before) => {
                out.push(Line::from(vec![
                    Span::styled(format!("~ {}", key(row)), yellow.add_modifier(Modifier::BOLD)),
                    Span::raw(format!("  {}", row.get(1).cloned().unwrap_or_default())),
                ]));
                for (i, name) in header.iter().enumerate().skip(1) {
                    let (a, b) = (before.get(i).cloned().unwrap_or_default(), row.get(i).cloned().unwrap_or_default());
                    if a != b {
                        out.push(Line::from(vec![
                            Span::styled(format!("    {name}: "), muted),
                            Span::styled(if a.is_empty() { "∅".into() } else { a }, red),
                            Span::raw(" → "),
                            Span::styled(if b.is_empty() { "∅".into() } else { b }, green),
                        ]));
                    }
                }
            }
            None => {
                out.push(Line::from(vec![
                    Span::styled(format!("+ {}", key(row)), green.add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  {}", row.get(1).cloned().unwrap_or_default()), green),
                ]));
                out.push(Line::styled(format!("    {}", row_facts(&header, row)), muted));
            }
        }
    }
    for row in removed.iter().filter(|r| !added.iter().any(|a| key(a) == key(r))) {
        out.push(Line::from(vec![
            Span::styled(format!("- {}", key(row)), red.add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {}", row.get(1).cloned().unwrap_or_default()), red),
        ]));
    }
    let prose: Vec<(Op, String)> = ops.into_iter().filter(|(o, l)| *o != Op::Same && !l.starts_with('|')).collect();
    out.extend(fold_same_runs(prose));
    out
}

fn row_facts(header: &[String], row: &[String]) -> String {
    header
        .iter()
        .zip(row)
        .skip(2)
        .filter(|(_, v)| !v.is_empty())
        .map(|(h, v)| format!("{h} {v}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn fold_same_runs(ops: Vec<(Op, String)>) -> Vec<Line<'static>> {
    let muted = Style::default().fg(Color::DarkGray);
    let mut out = Vec::new();
    let mut run: Vec<String> = Vec::new();
    let flush = |run: &mut Vec<String>, out: &mut Vec<Line<'static>>| {
        let keep: Vec<&String> = run.iter().filter(|l| is_table_scaffold(l)).collect();
        let folded = run.len() - keep.len();
        for l in keep {
            out.push(Line::styled(format!("  {l}"), muted));
        }
        if folded > 0 {
            out.push(Line::styled(format!("  ⋯ {folded} unchanged line(s)"), muted));
        }
        run.clear();
    };
    for (op, text) in ops {
        match op {
            Op::Same => run.push(text),
            Op::Add | Op::Del => {
                flush(&mut run, &mut out);
                let (sign, color) = if op == Op::Add { ("+ ", Color::Green) } else { ("- ", Color::Red) };
                out.push(Line::styled(format!("{sign}{text}"), Style::default().fg(color)));
            }
        }
    }
    flush(&mut run, &mut out);
    out
}

// ───────────────────── edits → JSON merge patch ─────────────────────

pub struct EditOutcome {
    /// Top-level JSON merge patch (arrays replace wholesale).
    pub patch: Value,
    pub document: Value,
    /// Human-readable list of what was mapped.
    pub applied: Vec<String>,
    /// Sections edited that have no structural mapping.
    pub unmapped: Vec<String>,
}

pub fn compile_edits(document: &Value, original_md: &str, edited_md: &str) -> EditOutcome {
    let (before, after) = (sections(original_md), sections(edited_md));
    let mut patch = Map::new();
    let (mut applied, mut unmapped) = (Vec::new(), Vec::new());
    for s in &after {
        let old = before.iter().find(|b| b.heading == s.heading);
        if old.is_some_and(|o| o.body == s.body) {
            continue;
        }
        let name = short_heading(&s.heading);
        let mapped = match s.heading.as_str() {
            h if h.starts_with("## 1.") => {
                patch.insert("systemContext".into(), json!(s.body.join("\n").trim()));
                Some("system context prose".to_string())
            }
            h if h.starts_with("## 2.") => Some(apply_assets(document, s, &mut patch)),
            h if h.starts_with("## 4.") => Some(apply_threats(document, s, &mut patch)),
            h if h.starts_with("## 6.") => {
                let questions: Vec<Value> = s
                    .body
                    .iter()
                    .filter_map(|l| l.trim().strip_prefix("- "))
                    .map(|q| json!({"question": q.trim()}))
                    .collect();
                let n = questions.len();
                patch.insert("openQuestions".into(), Value::Array(questions));
                Some(format!("open questions ({n})"))
            }
            h if h.starts_with("## 8.") => Some(apply_mitigations(s, &mut patch)),
            _ => None,
        };
        match mapped {
            Some(what) => applied.push(what),
            None => unmapped.push(name),
        }
    }
    for gone in before.iter().filter(|b| !after.iter().any(|a| a.heading == b.heading)) {
        unmapped.push(format!("{} (heading removed/renamed)", short_heading(&gone.heading)));
    }
    let mut next = document.clone();
    for (k, v) in &patch {
        next[k.as_str()] = v.clone();
    }
    EditOutcome { patch: Value::Object(patch), document: next, applied, unmapped }
}

/// Table data rows (header + separator skipped), cells unescaped.
fn table_rows(section: &Section) -> Vec<Vec<String>> {
    section
        .body
        .iter()
        .filter(|l| l.trim_start().starts_with('|'))
        .skip(2)
        .map(|l| split_row(l.trim()))
        .collect()
}

fn split_row(line: &str) -> Vec<String> {
    let inner = line.trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = vec![String::new()];
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cells.last_mut().unwrap().push('|');
                chars.next();
            }
            '|' => cells.push(String::new()),
            _ => cells.last_mut().unwrap().push(c),
        }
    }
    cells.iter().map(|c| c.trim().to_string()).collect()
}

fn cell(row: &[String], i: usize) -> String {
    row.get(i).cloned().unwrap_or_default()
}

fn rows_of(document: &Value, key: &str) -> Vec<Value> {
    document.get(key).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn threat_key_matches(threat: &Value, id: &str) -> bool {
    ["displayId", "stableId", "id"]
        .iter()
        .any(|k| threat.get(*k).and_then(Value::as_str) == Some(id))
}

fn apply_threats(document: &Value, section: &Section, patch: &mut Map<String, Value>) -> String {
    let existing = rows_of(document, "threats");
    let (mut updated, mut added) = (0, 0);
    let threats: Vec<Value> = table_rows(section)
        .into_iter()
        .filter(|row| !cell(row, 0).is_empty())
        .map(|row| {
            let id = cell(&row, 0);
            let mut threat = match existing.iter().find(|t| threat_key_matches(t, &id)) {
                Some(t) => {
                    updated += 1;
                    t.clone()
                }
                None => {
                    added += 1;
                    json!({"id": id, "displayId": id, "stableId": format!("op-{id}"), "targetElementIds": []})
                }
            };
            for (i, field) in [(1, "title"), (2, "actor"), (3, "surface"), (4, "asset"), (5, "impact"), (6, "likelihood"), (7, "status")] {
                threat[field] = json!(cell(&row, i));
            }
            threat
        })
        .collect();
    let removed = existing.len().saturating_sub(updated);
    patch.insert("threats".into(), Value::Array(threats));
    format!("threats table ({updated} kept/edited · {added} added · {removed} removed)")
}

fn apply_assets(document: &Value, section: &Section, patch: &mut Map<String, Value>) -> String {
    let existing = rows_of(document, "assets");
    let assets: Vec<Value> = table_rows(section)
        .into_iter()
        .enumerate()
        .filter(|(_, row)| !cell(row, 0).is_empty())
        .map(|(i, row)| {
            let name = cell(&row, 0);
            let mut asset = existing
                .iter()
                .find(|a| a.get("asset").and_then(Value::as_str) == Some(name.as_str()))
                .cloned()
                .unwrap_or_else(|| json!({"id": format!("A-op-{i}"), "targetElementIds": []}));
            asset["asset"] = json!(name);
            asset["description"] = json!(cell(&row, 1));
            asset["sensitivity"] = json!(cell(&row, 2));
            asset
        })
        .collect();
    let n = assets.len();
    patch.insert("assets".into(), Value::Array(assets));
    format!("assets table ({n} rows)")
}

fn apply_mitigations(section: &Section, patch: &mut Map<String, Value>) -> String {
    let rows: Vec<Value> = table_rows(section)
        .into_iter()
        .filter(|row| !cell(row, 0).is_empty())
        .map(|row| {
            json!({
                "mitigation": cell(&row, 0),
                "threatIds": cell(&row, 1).split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>(),
                "closesClass": cell(&row, 2),
                "effort": cell(&row, 3),
            })
        })
        .collect();
    let n = rows.len();
    patch.insert("recommendedMitigations".into(), Value::Array(rows));
    format!("recommended mitigations ({n} rows)")
}
