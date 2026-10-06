//! Conservative source bindings for Python receivers with shared HTTP syntax.
use std::collections::BTreeMap;

type FrameworkBindings = BTreeMap<String, Option<&'static str>>;

#[derive(Default)]
pub(super) struct PythonRouteFrameworks {
    receivers: FrameworkBindings,
}

impl PythonRouteFrameworks {
    pub(super) fn from_source(source: &str) -> Self {
        let mut constructors = FrameworkBindings::new();
        let mut receivers = FrameworkBindings::new();
        for line in source.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            record_import(line, &mut constructors);
            record_definition_shadow(line, &mut constructors);
            record_assignment(line, &mut constructors, &mut receivers);
        }
        Self { receivers }
    }

    pub(super) fn framework(&self, receiver: &str) -> Option<&'static str> {
        self.receivers.get(receiver).copied().flatten()
    }
}

fn record_definition_shadow(line: &str, constructors: &mut FrameworkBindings) {
    let Some(rest) = line
        .strip_prefix("def ")
        .or_else(|| line.strip_prefix("class "))
    else {
        return;
    };
    let name = rest.split(['(', ':']).next().unwrap_or_default().trim();
    if constructors.contains_key(name) {
        record_binding(constructors, name, None);
    }
}

fn record_import(line: &str, bindings: &mut FrameworkBindings) {
    if let Some(rest) = line.strip_prefix("from ") {
        record_constructor_import(rest, bindings);
    } else if let Some(rest) = line.strip_prefix("import ") {
        record_module_import(rest, bindings);
    }
}

fn record_constructor_import(rest: &str, bindings: &mut FrameworkBindings) {
    let Some((module, names)) = rest.split_once(" import ") else {
        return;
    };
    for item in names.split(',') {
        let Some((name, alias)) = import_name(item.trim()) else {
            continue;
        };
        let Some(framework) = constructor_framework(module.trim(), name) else {
            continue;
        };
        record_binding(bindings, alias, Some(framework));
    }
}

fn record_module_import(rest: &str, bindings: &mut FrameworkBindings) {
    for item in rest.split(',') {
        let Some((module, alias)) = import_name(item.trim()) else {
            continue;
        };
        record_module_constructors(bindings, module, alias);
    }
}

fn record_module_constructors(bindings: &mut FrameworkBindings, module: &str, alias: &str) {
    for constructor in [
        "Flask",
        "Blueprint",
        "FastAPI",
        "APIRouter",
        "Sanic",
        "Starlette",
    ] {
        if let Some(framework) = constructor_framework(module, constructor) {
            record_binding(bindings, &format!("{alias}.{constructor}"), Some(framework));
        }
    }
}

fn import_name(item: &str) -> Option<(&str, &str)> {
    let (name, alias) = item.split_once(" as ").unwrap_or((item, item));
    (identifier_path(name) && identifier_path(alias)).then_some((name, alias))
}

fn constructor_framework(module: &str, name: &str) -> Option<&'static str> {
    match (module, name) {
        ("flask", "Flask" | "Blueprint") => Some("Flask"),
        ("fastapi", "FastAPI" | "APIRouter") => Some("FastAPI"),
        ("sanic", "Sanic" | "Blueprint") => Some("Sanic"),
        ("starlette.applications", "Starlette") => Some("Starlette"),
        _ => None,
    }
}

fn record_assignment(
    line: &str,
    constructors: &mut FrameworkBindings,
    receivers: &mut FrameworkBindings,
) {
    let Some((name, value)) = assignment(line) else {
        return;
    };
    let constructor = value.split('(').next().unwrap_or_default().trim();
    let framework = constructors.get(constructor).copied().flatten();
    if constructors.contains_key(name) {
        record_binding(constructors, name, None);
    }
    record_binding(receivers, name, framework);
}

fn assignment(line: &str) -> Option<(&str, &str)> {
    let (left, right) = line.split_once('=')?;
    let name = left.split(':').next()?.trim();
    let value = right.trim();
    (identifier_path(name) && !value.starts_with('=')).then_some((name, value))
}

fn identifier_path(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(identifier)
}

fn identifier(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && value
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || letter == '_')
}

fn record_binding(bindings: &mut FrameworkBindings, name: &str, framework: Option<&'static str>) {
    bindings
        .entry(name.to_string())
        .and_modify(|prior| {
            if *prior != framework {
                *prior = None;
            }
        })
        .or_insert(framework);
}

#[cfg(test)]
mod tests;
