use super::*;

pub(super) fn inspect_command_execution(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !inspection.has_any(&[
        "child_process.exec",
        "child_process.spawn",
        "execfile(",
        "exec(",
        "spawn(",
        "execa(",
    ]) {
        return;
    }
    let route = inspection.route();
    inspection.add_surface(
        builder,
        AttackSurfaceKind::CommandExecutionBoundary,
        "Command execution boundary",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("process_execution"),
        "node.command-exec",
    );
}

pub(super) fn inspect_cli_entrypoint(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !inspection.lower.contains("process.argv")
        && !inspection.detail.starts_with("#!/usr/bin/env node")
    {
        return;
    }
    inspection.add_surface(
        builder,
        AttackSurfaceKind::CliEntrypoint,
        "CLI argument entrypoint",
        None,
        None,
        Some("process_entrypoint"),
        "node.cli-entrypoint",
    );
}
