use super::*;

pub(crate) fn inspect_go_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    if line_contains_any(&lower, &["authmiddleware", "requireuser", "authorize"]) {
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Authentication or authorization guard",
            &detail,
            None,
            None,
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "go.auth-guard" }),
        ));
    }
    if line_contains_any(&lower, &["json.newdecoder", "yaml.", "proto.unmarshal"]) {
        builder.add(surface(
            AttackSurfaceKind::DeserializationPoint,
            source_file,
            framework,
            line_number,
            "Deserialization or parser boundary",
            &detail,
            None,
            None,
            Some("parser_boundary"),
            json!({ "source": "source_line", "detector": "go.deserialization" }),
        ));
    }
    if line_contains_any(&lower, &[".query(", ".exec(", "db."]) {
        builder.add(surface(
            AttackSurfaceKind::DbQueryBoundary,
            source_file,
            framework,
            line_number,
            "Database query boundary",
            &detail,
            None,
            None,
            Some("data_store"),
            json!({ "source": "source_line", "detector": "go.db-query" }),
        ));
    }
    if line_contains_any(&lower, &["exec.command(", "os.startprocess("]) {
        builder.add(surface(
            AttackSurfaceKind::CommandExecutionBoundary,
            source_file,
            framework,
            line_number,
            "Command execution boundary",
            &detail,
            None,
            None,
            Some("process_execution"),
            json!({ "source": "source_line", "detector": "go.command-exec" }),
        ));
    }
}
