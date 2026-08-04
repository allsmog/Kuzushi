use super::*;

mod item_header;
mod registration;
mod rust_mask;

use item_header::function_header;
#[cfg(test)]
use item_header::ITEM_HEADER_LINE_LIMIT;
use registration::registered_tauri_handlers;
use rust_mask::rust_code_view;
use std::collections::BTreeSet;

const TAURI_COMMAND_ATTRIBUTE: &str = "#[tauri::command";

#[derive(Debug, PartialEq, Eq)]
struct TauriCommandFunction {
    attribute_line: u32,
    function_line: u32,
    name: String,
    evidence: String,
    cfg_predicates: Vec<String>,
}

#[derive(Debug)]
struct TauriCommandDefinition {
    source_file: InventorySourceFile,
    handler_path: String,
    command: TauriCommandFunction,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TauriCommandRegistration {
    source_path: String,
    line: u32,
    handler_path: String,
    definition_path: String,
}

#[derive(Debug, Default)]
pub(crate) struct TauriCommandCatalog {
    definitions: Vec<TauriCommandDefinition>,
    registrations: BTreeMap<String, BTreeSet<TauriCommandRegistration>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttributeSpan {
    start: usize,
    end: usize,
}

pub(crate) fn inspect_rust_tauri_commands(
    source_file: &InventorySourceFile,
    text: &str,
    catalog: &mut TauriCommandCatalog,
) {
    catalog.collect(source_file, text);
}

impl TauriCommandCatalog {
    fn collect(&mut self, source_file: &InventorySourceFile, text: &str) {
        self.collect_definitions(source_file, text);
        self.collect_registrations(source_file, text);
    }

    fn collect_definitions(&mut self, source_file: &InventorySourceFile, text: &str) {
        self.definitions
            .extend(tauri_command_functions(text).into_iter().map(|command| {
                TauriCommandDefinition {
                    handler_path: definition_path(&source_file.path, &command.name),
                    source_file: source_file.clone(),
                    command,
                }
            }));
    }

    fn collect_registrations(&mut self, source_file: &InventorySourceFile, text: &str) {
        for handler in registered_tauri_handlers(text) {
            let logical_name = handler.logical_name.clone();
            let registration = TauriCommandRegistration {
                source_path: source_file.path.clone(),
                line: handler.line,
                definition_path: registered_definition_path(&source_file.path, &handler.path),
                handler_path: handler.path,
            };
            self.registrations
                .entry(logical_name)
                .or_default()
                .insert(registration);
        }
    }

    pub(crate) fn add_registered_surfaces(self, builder: &mut AttackSurfaceBuilder) {
        let Self {
            definitions,
            registrations,
        } = self;
        for definition in definitions {
            let Some(candidates) = registrations.get(&definition.command.name) else {
                continue;
            };
            let receipts = matching_registrations(&definition.handler_path, candidates);
            if !receipts.is_empty() {
                builder.add(tauri_command_surface(&definition, &receipts));
            }
        }
    }
}

fn matching_registrations<'a>(
    definition_path: &str,
    registrations: &'a BTreeSet<TauriCommandRegistration>,
) -> Vec<&'a TauriCommandRegistration> {
    registrations
        .iter()
        .filter(|registration| registration.definition_path == definition_path)
        .collect()
}

fn definition_path(source_path: &str, handler_name: &str) -> String {
    let mut segments = source_module_segments(source_path);
    segments.push(handler_name.to_string());
    scoped_definition_path(source_path, &segments)
}

fn registered_definition_path(source_path: &str, handler_path: &str) -> String {
    let mut handler_segments = handler_path.split("::").collect::<Vec<_>>();
    let mut module_segments = source_module_segments(source_path);
    resolve_registration_prefix(&mut module_segments, &mut handler_segments);
    module_segments.extend(handler_segments.into_iter().map(str::to_string));
    scoped_definition_path(source_path, &module_segments)
}

fn scoped_definition_path(source_path: &str, segments: &[String]) -> String {
    format!("{}|{}", source_crate_scope(source_path), segments.join("::"))
}

fn source_crate_scope(source_path: &str) -> &str {
    source_path
        .rfind("/src/")
        .map_or(".", |index| &source_path[..index])
}

fn resolve_registration_prefix(module_segments: &mut Vec<String>, path: &mut Vec<&str>) {
    match path.first().copied() {
        Some("crate") => {
            module_segments.clear();
            path.remove(0);
        }
        Some("self") => {
            path.remove(0);
        }
        Some("super") => {
            module_segments.pop();
            path.remove(0);
        }
        Some(_) if path.len() > 1 => module_segments.clear(),
        _ => {}
    }
}

fn source_module_segments(source_path: &str) -> Vec<String> {
    let path_segments = source_path.split('/').collect::<Vec<_>>();
    let start = path_segments
        .iter()
        .rposition(|segment| *segment == "src")
        .map_or(0, |index| index + 1);
    let mut modules = path_segments[start..].to_vec();
    normalize_module_file(&mut modules);
    modules.into_iter().map(str::to_string).collect()
}

fn normalize_module_file(modules: &mut Vec<&str>) {
    let Some(file) = modules.pop() else {
        return;
    };
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    if !matches!(stem, "lib" | "main" | "mod") {
        modules.push(stem);
    }
}

fn tauri_command_functions(text: &str) -> Vec<TauriCommandFunction> {
    let code = rust_code_view(text);
    let attributes = attribute_spans(&code);
    let line_starts = line_starts(&code);
    attributes
        .iter()
        .enumerate()
        .filter(|(_, attribute)| is_tauri_command_attribute(&code[attribute.start..attribute.end]))
        .filter_map(|(index, attribute)| {
            command_after_attribute(text, &code, &attributes, &line_starts, index, *attribute)
        })
        .collect()
}

fn command_after_attribute(
    source: &str,
    code: &str,
    attributes: &[AttributeSpan],
    line_starts: &[usize],
    index: usize,
    command_attribute: AttributeSpan,
) -> Option<TauriCommandFunction> {
    let group = adjacent_attribute_group(code, attributes, index);
    let header_start = attributes[group.end - 1].end;
    let header = function_header(code, header_start)?;
    let cfg_predicates = cfg_predicates(source, &attributes[group]);
    let declaration = source_declaration(source, header.function_offset);
    Some(TauriCommandFunction {
        attribute_line: line_number(line_starts, command_attribute.start),
        function_line: line_number(line_starts, header.function_offset),
        name: header.name.to_string(),
        evidence: command_evidence(declaration, &cfg_predicates),
        cfg_predicates,
    })
}

fn attribute_spans(code: &str) -> Vec<AttributeSpan> {
    let bytes = code.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes.get(index..index + 2) != Some(b"#[") {
            index += 1;
            continue;
        }
        let Some(end) = attribute_end(bytes, index) else {
            index += 2;
            continue;
        };
        spans.push(AttributeSpan { start: index, end });
        index = end;
    }
    spans
}

fn attribute_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0isize;
    for (offset, byte) in bytes.get(start + 1..)?.iter().enumerate() {
        depth += isize::from(*byte == b'[');
        depth -= isize::from(*byte == b']');
        if depth == 0 {
            return Some(start + offset + 2);
        }
    }
    None
}

fn is_tauri_command_attribute(attribute: &str) -> bool {
    let Some(suffix) = attribute.strip_prefix(TAURI_COMMAND_ATTRIBUTE) else {
        return false;
    };
    matches!(suffix.chars().next(), None | Some(']' | '('))
        || suffix.chars().next().is_some_and(char::is_whitespace)
}

fn adjacent_attribute_group(
    code: &str,
    attributes: &[AttributeSpan],
    command_index: usize,
) -> std::ops::Range<usize> {
    let mut start = command_index;
    while start > 0 && only_whitespace(code, attributes[start - 1].end, attributes[start].start) {
        start -= 1;
    }
    let mut end = command_index + 1;
    while end < attributes.len()
        && only_whitespace(code, attributes[end - 1].end, attributes[end].start)
    {
        end += 1;
    }
    start..end
}

fn only_whitespace(code: &str, start: usize, end: usize) -> bool {
    code.get(start..end)
        .is_some_and(|between| between.chars().all(char::is_whitespace))
}

fn cfg_predicates(source: &str, attributes: &[AttributeSpan]) -> Vec<String> {
    attributes
        .iter()
        .filter_map(|attribute| cfg_predicate(source.get(attribute.start..attribute.end)?))
        .collect()
}

fn cfg_predicate(attribute: &str) -> Option<String> {
    let compact = attribute.split_whitespace().collect::<Vec<_>>().join(" ");
    let body = compact.strip_prefix("#[")?.strip_suffix(']')?.trim();
    let arguments = body.strip_prefix("cfg")?.trim_start();
    let predicate = arguments.strip_prefix('(')?.strip_suffix(')')?.trim();
    (!predicate.is_empty()).then(|| predicate.to_string())
}

fn command_evidence(declaration: &str, predicates: &[String]) -> String {
    let declaration = trim_detail(declaration);
    if predicates.is_empty() {
        declaration
    } else {
        format!("{declaration} [cfg: {}]", predicates.join(" && "))
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .collect()
}

fn line_number(line_starts: &[usize], offset: usize) -> u32 {
    let index = line_starts.partition_point(|start| *start <= offset);
    u32::try_from(index).unwrap_or(u32::MAX)
}

fn source_declaration(source: &str, offset: usize) -> &str {
    let end = source[offset..]
        .find('\n')
        .map_or(source.len(), |relative| offset + relative);
    &source[offset..end]
}

fn tauri_command_surface(
    definition: &TauriCommandDefinition,
    registrations: &[&TauriCommandRegistration],
) -> AttackSurfaceDraft {
    let command = &definition.command;
    surface(
        AttackSurfaceKind::RpcHandler,
        &definition.source_file,
        Some("Tauri"),
        command.function_line,
        &format!("Tauri command: {}", command.name),
        &command.evidence,
        None,
        Some(&command.name),
        Some("native_command"),
        command_metadata(command, registrations),
    )
}

fn command_metadata(
    command: &TauriCommandFunction,
    registrations: &[&TauriCommandRegistration],
) -> Value {
    let mut metadata = json!({
        "source": "source_file",
        "detector": "rust.tauri-command",
        "handler": command.name,
        "attributeLine": command.attribute_line,
        "reachability": "registered",
        "registrationSites": registration_sites(registrations),
    });
    if !command.cfg_predicates.is_empty() {
        metadata["cfgPredicates"] = json!(command.cfg_predicates);
    }
    metadata
}

fn registration_sites(registrations: &[&TauriCommandRegistration]) -> Value {
    json!(registrations
        .iter()
        .map(|registration| json!({
            "path": registration.source_path,
            "line": registration.line,
            "handlerPath": registration.handler_path,
        }))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests;
