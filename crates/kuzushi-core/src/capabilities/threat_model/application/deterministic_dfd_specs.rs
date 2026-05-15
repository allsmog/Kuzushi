use crate::attack_surface::AttackSurfaceKind;
use serde_json::{json, Value};

use super::deterministic_dfd_surface_specs::{
    surface_dfd_flows, surface_dfd_nodes, surface_trust_boundaries,
};

pub(super) fn optional_dfd_nodes() -> Vec<(AttackSurfaceKind, Value)> {
    let mut nodes = vec![
        (AttackSurfaceKind::DbQueryBoundary, data_store_node()),
        (
            AttackSurfaceKind::CommandExecutionBoundary,
            process_execution_node(),
        ),
        (
            AttackSurfaceKind::ExternalServiceClient,
            external_service_node(),
        ),
        (AttackSurfaceKind::AuthBoundary, auth_control_node()),
        (AttackSurfaceKind::SessionStateBoundary, session_state_node()),
        (
            AttackSurfaceKind::RequestTrustBoundary,
            request_trust_node(),
        ),
        (
            AttackSurfaceKind::TenantIsolationBoundary,
            tenant_isolation_node(),
        ),
    ];
    nodes.extend(surface_dfd_nodes());
    nodes
}

pub(super) fn optional_dfd_flows() -> Vec<(AttackSurfaceKind, Value)> {
    let mut flows = vec![
        (AttackSurfaceKind::DbQueryBoundary, data_store_flow()),
        (
            AttackSurfaceKind::CommandExecutionBoundary,
            process_execution_flow(),
        ),
        (
            AttackSurfaceKind::ExternalServiceClient,
            external_service_flow(),
        ),
        (AttackSurfaceKind::AuthBoundary, auth_control_flow()),
        (AttackSurfaceKind::SessionStateBoundary, session_state_flow()),
        (
            AttackSurfaceKind::RequestTrustBoundary,
            request_trust_flow(),
        ),
        (
            AttackSurfaceKind::TenantIsolationBoundary,
            tenant_isolation_flow(),
        ),
    ];
    flows.extend(surface_dfd_flows());
    flows
}

pub(super) fn optional_trust_boundaries() -> Vec<(AttackSurfaceKind, Value)> {
    let mut boundaries = base_trust_boundaries();
    boundaries.extend(surface_trust_boundaries());
    boundaries
}

fn base_trust_boundaries() -> Vec<(AttackSurfaceKind, Value)> {
    BASE_TRUST_BOUNDARY_SPECS
        .iter()
        .map(|(kind, id, name, flow)| (*kind, trust_boundary(id, name, flow)))
        .collect()
}

const BASE_TRUST_BOUNDARY_SPECS: &[(AttackSurfaceKind, &str, &str, &str)] = &[
    (
        AttackSurfaceKind::ExternalServiceClient,
        "tb-outbound-service",
        "Outbound service boundary",
        "flow-external-service",
    ),
    (
        AttackSurfaceKind::AuthBoundary,
        "tb-auth-boundary",
        "Authentication boundary",
        "flow-auth-control",
    ),
    (
        AttackSurfaceKind::SessionStateBoundary,
        "tb-session-state",
        "Session state boundary",
        "flow-session-state",
    ),
    (
        AttackSurfaceKind::RequestTrustBoundary,
        "tb-request-trust",
        "Request trust boundary",
        "flow-request-trust",
    ),
    (
        AttackSurfaceKind::TenantIsolationBoundary,
        "tb-tenant-isolation",
        "Tenant isolation boundary",
        "flow-tenant-isolation",
    ),
];

pub(super) fn dfd_node(
    id: &str,
    node_type: &str,
    name: &str,
    description: &str,
    trust_zone: &str,
) -> Value {
    json!({
        "id": id,
        "type": node_type,
        "name": name,
        "description": description,
        "trustZone": trust_zone,
    })
}

pub(super) fn dfd_flow(
    id: &str,
    description: &str,
    source: &str,
    target: &str,
    boundaries: &[&str],
) -> Value {
    json!({
        "id": id,
        "description": description,
        "sourceId": source,
        "targetId": target,
        "trustBoundaryIds": boundaries,
    })
}

fn data_store_node() -> Value {
    dfd_node(
        "data-store",
        "data-store",
        "Data store",
        "Detected database boundary",
        "internal",
    )
}

fn process_execution_node() -> Value {
    dfd_node(
        "process-execution",
        "process",
        "Process execution",
        "Detected command execution boundary",
        "host",
    )
}

fn external_service_node() -> Value {
    dfd_node(
        "external-service",
        "external-entity",
        "External service",
        "Detected outbound service dependency",
        "external",
    )
}

fn auth_control_node() -> Value {
    dfd_node(
        "auth-control",
        "process",
        "Auth control",
        "Detected authentication or authorization guard",
        "internal",
    )
}

fn session_state_node() -> Value {
    dfd_node(
        "session-state",
        "data-store",
        "Session state",
        "Detected session or token state boundary",
        "internal",
    )
}

fn request_trust_node() -> Value {
    dfd_node(
        "request-trust-control",
        "process",
        "Request trust control",
        "Detected CSRF, CORS, or same-site request boundary",
        "internal",
    )
}

fn tenant_isolation_node() -> Value {
    dfd_node(
        "tenant-isolation-control",
        "process",
        "Tenant isolation control",
        "Detected tenant, organization, or workspace boundary",
        "internal",
    )
}

fn data_store_flow() -> Value {
    dfd_flow(
        "flow-data-store",
        "Application data-store access",
        "app",
        "data-store",
        &[],
    )
}

fn process_execution_flow() -> Value {
    dfd_flow(
        "flow-process-exec",
        "Application process execution",
        "app",
        "process-execution",
        &[],
    )
}

fn external_service_flow() -> Value {
    dfd_flow(
        "flow-external-service",
        "Application outbound service call",
        "app",
        "external-service",
        &["tb-outbound-service"],
    )
}

fn auth_control_flow() -> Value {
    dfd_flow(
        "flow-auth-control",
        "External request crosses authentication or authorization guard",
        "actor-external",
        "auth-control",
        &["tb-auth-boundary"],
    )
}

fn session_state_flow() -> Value {
    dfd_flow(
        "flow-session-state",
        "External session material reaches session state handling",
        "actor-external",
        "session-state",
        &["tb-session-state"],
    )
}

fn request_trust_flow() -> Value {
    dfd_flow(
        "flow-request-trust",
        "External request crosses CSRF, CORS, or same-site controls",
        "actor-external",
        "request-trust-control",
        &["tb-request-trust"],
    )
}

fn tenant_isolation_flow() -> Value {
    dfd_flow(
        "flow-tenant-isolation",
        "External tenant-scoped request crosses isolation control",
        "actor-external",
        "tenant-isolation-control",
        &["tb-tenant-isolation"],
    )
}

pub(super) fn trust_boundary(id: &str, name: &str, crossing_flow_id: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "innerZone": "internal",
        "outerZone": "external",
        "crossingFlowIds": [crossing_flow_id],
    })
}
