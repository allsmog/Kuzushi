use super::*;

pub(in crate::code_nav::symbol_index) mod classification;
mod types;

use classification::classify_hit;
pub use types::{ReadDefinitionInput, ReadDefinitionOutput};

pub fn read_definition(root: &Path, input: &ReadDefinitionInput) -> Result<ReadDefinitionOutput> {
    let symbol = input.name.trim();
    anyhow::ensure!(
        !symbol.is_empty(),
        "read_definition: name must be non-empty"
    );

    let refs = find_references(
        root,
        &FindReferencesInput {
            symbol: symbol.to_string(),
            scope: input.hint_file.clone(),
            language: None,
        },
    )?;

    let mut candidates: Vec<DefinitionEntry> = refs
        .hits
        .into_iter()
        .filter_map(|hit| {
            classify_hit(&hit.snippet, symbol)
                .map(|kind| DefinitionEntry {
                    name: symbol.to_string(),
                    kind,
                    line: hit.line,
                    signature: hit.snippet.clone(),
                })
                .map(|entry| (hit.file, entry))
        })
        .map(|(file, mut entry)| {
            entry.signature = format!("{}:{}\t{}", file, entry.line, entry.signature);
            (file, entry)
        })
        .map(|(_file, e)| e)
        .collect();

    let primary = candidates
        .pop()
        .ok_or_else(|| anyhow::anyhow!("read_definition: no definition for {symbol:?}"))?;

    let (file_line_marker, signature) = primary
        .signature
        .split_once('\t')
        .unwrap_or(("", primary.signature.as_str()));
    let (file, _line_str) = file_line_marker
        .split_once(':')
        .unwrap_or(("", file_line_marker));
    let source_window = read_source(
        root,
        &ReadSourceInput {
            file: file.to_string(),
            start_line: Some(primary.line.saturating_sub(2).max(1)),
            end_line: Some(primary.line + 30),
        },
    )?;

    Ok(ReadDefinitionOutput {
        name: symbol.to_string(),
        file: file.to_string(),
        line: primary.line,
        kind: primary.kind,
        signature: signature.to_string(),
        source: source_window.contents,
        also_seen: candidates,
    })
}
