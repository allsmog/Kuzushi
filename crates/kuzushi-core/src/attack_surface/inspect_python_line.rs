use super::*;

pub(crate) fn inspect_python_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    if lower.contains("login_required") || lower.contains("permission_required") {
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
            json!({ "source": "source_line", "detector": "python.auth-guard" }),
        ));
    }
    if line_contains_any(&lower, &["pickle.loads", "yaml.load(", "json.loads("]) {
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
            json!({ "source": "source_line", "detector": "python.deserialization" }),
        ));
    }
    if line_contains_any(&lower, &["cursor.execute", ".execute(", "session.execute("]) {
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
            json!({ "source": "source_line", "detector": "python.db-query" }),
        ));
    }
    if line_contains_any(&lower, &["shell=true", "subprocess.", "os.system("]) {
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
            json!({ "source": "source_line", "detector": "python.command-exec" }),
        ));
    }
}
