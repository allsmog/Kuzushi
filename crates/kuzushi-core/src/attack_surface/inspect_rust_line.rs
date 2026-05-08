use super::*;

pub(crate) fn inspect_rust_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    for detector in RUST_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

struct RustLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl RustLineDetector {
    fn matches(&self, line: &str) -> bool {
        line_contains_any(line, self.needles)
    }

    fn surface(
        &self,
        source_file: &InventorySourceFile,
        framework: Option<&str>,
        line_number: u32,
        detail: &str,
    ) -> AttackSurfaceDraft {
        surface(
            self.kind,
            source_file,
            framework,
            line_number,
            self.title,
            detail,
            None,
            None,
            Some(self.boundary),
            json!({ "source": "source_line", "detector": self.detector }),
        )
    }
}

const RUST_LINE_DETECTORS: &[RustLineDetector] = &[
    RustLineDetector {
        kind: AttackSurfaceKind::AuthBoundary,
        title: "Authentication or authorization guard",
        boundary: "auth_guard",
        detector: "rust.auth-guard",
        needles: &["require_user", "requireuser", "authorize"],
    },
    RustLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "rust.deserialization",
        needles: &["serde_json::from", "serde_yaml::from", "bincode::"],
    },
    RustLineDetector {
        kind: AttackSurfaceKind::DbQueryBoundary,
        title: "Database query boundary",
        boundary: "data_store",
        detector: "rust.db-query",
        needles: &["sqlx::query", ".execute(", ".fetch_"],
    },
    RustLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "rust.command-exec",
        needles: &["std::process::command", "tokio::process::command"],
    },
    RustLineDetector {
        kind: AttackSurfaceKind::CliEntrypoint,
        title: "CLI argument entrypoint",
        boundary: "process_entrypoint",
        detector: "rust.cli-entrypoint",
        needles: &["std::env::args"],
    },
];

pub(crate) fn surface(
    kind: AttackSurfaceKind,
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    title: &str,
    evidence: &str,
    method: Option<&str>,
    route: Option<&str>,
    boundary: Option<&str>,
    metadata: Value,
) -> AttackSurfaceDraft {
    AttackSurfaceDraft {
        kind,
        path: source_file.path.clone(),
        line: Some(line_number),
        language: source_file.language.clone(),
        framework: framework.map(str::to_string),
        title: title.to_string(),
        evidence: evidence.to_string(),
        method: method.map(str::to_string),
        route: route.map(str::to_string),
        boundary: boundary.map(str::to_string),
        metadata,
    }
}
