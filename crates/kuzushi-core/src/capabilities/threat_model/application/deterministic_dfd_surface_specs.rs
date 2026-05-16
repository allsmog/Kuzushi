use crate::attack_surface::AttackSurfaceKind;
use serde_json::Value;

use super::deterministic_dfd_specs::{dfd_flow, dfd_node, trust_boundary};

pub(super) fn surface_dfd_nodes() -> Vec<(AttackSurfaceKind, Value)> {
    vec![
        (AttackSurfaceKind::HttpRoute, http_route_node()),
        (AttackSurfaceKind::RpcHandler, rpc_handler_node()),
        (
            AttackSurfaceKind::FileUploadParsePath,
            file_upload_parser_node(),
        ),
        (
            AttackSurfaceKind::DeserializationPoint,
            parser_boundary_node(),
        ),
        (AttackSurfaceKind::CliEntrypoint, cli_entrypoint_node()),
        (AttackSurfaceKind::BackgroundJob, background_job_node()),
    ]
}

pub(super) fn surface_dfd_flows() -> Vec<(AttackSurfaceKind, Value)> {
    vec![
        (AttackSurfaceKind::HttpRoute, http_route_flow()),
        (AttackSurfaceKind::RpcHandler, rpc_handler_flow()),
        (
            AttackSurfaceKind::FileUploadParsePath,
            file_upload_parser_flow(),
        ),
        (
            AttackSurfaceKind::DeserializationPoint,
            parser_boundary_flow(),
        ),
        (AttackSurfaceKind::CliEntrypoint, cli_entrypoint_flow()),
        (AttackSurfaceKind::BackgroundJob, background_job_flow()),
    ]
}

pub(super) fn surface_trust_boundaries() -> Vec<(AttackSurfaceKind, Value)> {
    vec![
        (
            AttackSurfaceKind::RpcHandler,
            trust_boundary("tb-rpc-handler", "RPC handler boundary", "flow-rpc-handler"),
        ),
        (
            AttackSurfaceKind::FileUploadParsePath,
            trust_boundary(
                "tb-file-upload",
                "File upload parser boundary",
                "flow-file-upload",
            ),
        ),
        (
            AttackSurfaceKind::DeserializationPoint,
            trust_boundary(
                "tb-parser-boundary",
                "Parser boundary",
                "flow-parser-boundary",
            ),
        ),
        (
            AttackSurfaceKind::CliEntrypoint,
            trust_boundary(
                "tb-process-entrypoint",
                "Process entrypoint boundary",
                "flow-cli-entrypoint",
            ),
        ),
    ]
}

fn http_route_node() -> Value {
    dfd_node(
        "http-route",
        "process",
        "HTTP route",
        "Detected public HTTP route",
        "edge",
    )
}

fn rpc_handler_node() -> Value {
    dfd_node(
        "rpc-handler",
        "process",
        "RPC handler",
        "Detected RPC or GraphQL handler",
        "internal",
    )
}

fn file_upload_parser_node() -> Value {
    dfd_node(
        "file-upload-parser",
        "process",
        "File upload parser",
        "Detected file upload or multipart parser",
        "internal",
    )
}

fn parser_boundary_node() -> Value {
    dfd_node(
        "parser-boundary",
        "process",
        "Parser boundary",
        "Detected parser or deserialization boundary",
        "internal",
    )
}

fn cli_entrypoint_node() -> Value {
    dfd_node(
        "cli-entrypoint",
        "process",
        "CLI entrypoint",
        "Detected command-line argument entrypoint",
        "host",
    )
}

fn background_job_node() -> Value {
    dfd_node(
        "background-job",
        "process",
        "Background job",
        "Detected scheduler or queue consumer",
        "internal",
    )
}

fn http_route_flow() -> Value {
    dfd_flow(
        "flow-http-route",
        "External request reaches HTTP route",
        "actor-external",
        "http-route",
        &["tb-public-http"],
    )
}

fn rpc_handler_flow() -> Value {
    dfd_flow(
        "flow-rpc-handler",
        "External request reaches RPC handler",
        "actor-external",
        "rpc-handler",
        &["tb-rpc-handler"],
    )
}

fn file_upload_parser_flow() -> Value {
    dfd_flow(
        "flow-file-upload",
        "External file data reaches upload parser",
        "actor-external",
        "file-upload-parser",
        &["tb-file-upload"],
    )
}

fn parser_boundary_flow() -> Value {
    dfd_flow(
        "flow-parser-boundary",
        "External request data reaches parser boundary",
        "actor-external",
        "parser-boundary",
        &["tb-parser-boundary"],
    )
}

fn cli_entrypoint_flow() -> Value {
    dfd_flow(
        "flow-cli-entrypoint",
        "External command input reaches process entrypoint",
        "actor-external",
        "cli-entrypoint",
        &["tb-process-entrypoint"],
    )
}

fn background_job_flow() -> Value {
    dfd_flow(
        "flow-background-job",
        "Application schedules or consumes background work",
        "app",
        "background-job",
        &[],
    )
}
