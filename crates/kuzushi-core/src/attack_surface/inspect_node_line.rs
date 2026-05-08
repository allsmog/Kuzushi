use super::prelude::*;
use super::*;

pub(crate) fn inspect_node_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if detail.is_empty() {
        return;
    }
    let lower = detail.to_ascii_lowercase();

    if is_route_line(&lower) && line_has_auth_guard(&lower) {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Route auth boundary",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "node.express.auth-route" }),
        ));
    } else if line_has_auth_guard(&lower) {
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
            json!({ "source": "source_line", "detector": "node.auth-guard" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "graphqlhttp(",
            "new apolloserver",
            "apolloserver(",
            "createexpressmiddleware",
            "trpc.",
            ".procedure",
            "grpc",
        ],
    ) || node_route_from_line(line)
        .path
        .as_deref()
        .is_some_and(|route| route.to_ascii_lowercase().contains("graphql"))
    {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::RpcHandler,
            source_file,
            framework,
            line_number,
            "RPC handler",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("remote_rpc"),
            json!({ "source": "source_line", "detector": "node.rpc-handler" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "cron.schedule(",
            "new queue(",
            "queue(",
            "agenda.define(",
            ".process(",
            "setinterval(",
        ],
    ) {
        builder.add(surface(
            AttackSurfaceKind::BackgroundJob,
            source_file,
            framework,
            line_number,
            "Background job or scheduler",
            &detail,
            None,
            None,
            Some("async_job"),
            json!({ "source": "source_line", "detector": "node.background-job" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "json.parse(",
            "yaml.load(",
            "yaml.parse(",
            "deserialize(",
            ".deserialize(",
            "jwt.decode(",
            "protobuf.decode(",
        ],
    ) {
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
            json!({ "source": "source_line", "detector": "node.deserialization" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "multer(",
            "upload.single(",
            "upload.array(",
            "upload.fields(",
            "busboy(",
            "formidable(",
            "multipart",
            "parsemultipart",
        ],
    ) {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::FileUploadParsePath,
            source_file,
            framework,
            line_number,
            "File upload or multipart parser",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("file_input"),
            json!({ "source": "source_line", "detector": "node.file-upload" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            ".query(",
            "prisma.",
            "sequelize.query(",
            "mongoose.",
            "knex(",
            ".collection(",
        ],
    ) {
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
            json!({ "source": "source_line", "detector": "node.db-query" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "child_process.exec",
            "child_process.spawn",
            "execfile(",
            "exec(",
            "spawn(",
            "execa(",
        ],
    ) {
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
            json!({ "source": "source_line", "detector": "node.command-exec" }),
        ));
    }

    if lower.contains("process.argv") || detail.starts_with("#!/usr/bin/env node") {
        builder.add(surface(
            AttackSurfaceKind::CliEntrypoint,
            source_file,
            framework,
            line_number,
            "CLI argument entrypoint",
            &detail,
            None,
            None,
            Some("process_entrypoint"),
            json!({ "source": "source_line", "detector": "node.cli-entrypoint" }),
        ));
    }
}
