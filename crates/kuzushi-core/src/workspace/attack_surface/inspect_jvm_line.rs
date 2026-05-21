mod detectors;
mod routes;
mod spring_routes;

use super::*;
use detectors::JVM_LINE_DETECTOR_GROUPS;
pub(crate) use routes::inspect_jvm_routes;
use spring_routes::add_spring_routes;

pub(crate) fn inspect_jvm_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_jvm_import_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    add_spring_routes(source_file, framework, line_number, &detail, &lower, builder);
    add_jvm_detector_surfaces(source_file, framework, line_number, &detail, &lower, builder);
}

fn add_jvm_detector_surfaces(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    for detector_group in JVM_LINE_DETECTOR_GROUPS {
        for detector in *detector_group {
            if detector.matches(&lower) {
                builder.add(detector.surface(source_file, framework, line_number, detail));
            }
        }
    }
}

fn is_jvm_import_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("import ") || trimmed.starts_with("package ")
}

fn backend_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

fn first_quoted(value: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(candidate) = quoted_with(value, quote) {
            return Some(candidate);
        }
    }
    None
}

fn quoted_with(value: &str, quote: char) -> Option<String> {
    let start = value.find(quote)? + 1;
    let end = value[start..].find(quote)? + start;
    let candidate = value[start..end].trim();
    (!candidate.is_empty()).then(|| candidate.to_string())
}
