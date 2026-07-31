use crate::attack_surface::{AttackSurface, AttackSurfaceKind};
use serde_json::{json, Value};

use super::deterministic_dfd_specs::{
    dfd_flow, dfd_node, optional_dfd_flows, optional_dfd_nodes, optional_trust_boundaries,
    trust_boundary,
};

pub(super) fn deterministic_dfd(surfaces: &[AttackSurface]) -> Value {
    json!({
        "nodes": deterministic_nodes(surfaces),
        "flows": deterministic_flows(surfaces),
        "trustBoundaries": deterministic_trust_boundaries(surfaces),
    })
}

fn deterministic_nodes(surfaces: &[AttackSurface]) -> Vec<Value> {
    let mut nodes = vec![
        dfd_node(
            "actor-external",
            "external-entity",
            "External actor",
            "Repository user or caller",
            "external",
        ),
        dfd_node(
            "app",
            "process",
            "Application",
            "Repository application boundary",
            "internal",
        ),
    ];
    push_optional_nodes(surfaces, &mut nodes);
    nodes
}

fn push_optional_nodes(surfaces: &[AttackSurface], nodes: &mut Vec<Value>) {
    for (kind, node) in optional_dfd_nodes() {
        if has_surface_kind(surfaces, kind) {
            nodes.push(node);
        }
    }
}

fn deterministic_flows(surfaces: &[AttackSurface]) -> Vec<Value> {
    let mut flows = public_http_flow(surfaces).into_iter().collect::<Vec<_>>();
    for (kind, flow) in optional_dfd_flows() {
        if has_surface_kind(surfaces, kind) {
            flows.push(flow);
        }
    }
    flows
}

fn public_http_flow(surfaces: &[AttackSurface]) -> Option<Value> {
    has_public_http_surface(surfaces).then(|| {
        dfd_flow(
            "flow-public-http",
            "Public request",
            "actor-external",
            "app",
            &["tb-public-http"],
        )
    })
}

fn deterministic_trust_boundaries(surfaces: &[AttackSurface]) -> Vec<Value> {
    let mut boundaries = Vec::new();
    if has_surface_kind(surfaces, AttackSurfaceKind::HttpRoute) || has_public_http_surface(surfaces)
    {
        boundaries.push(trust_boundary(
            "tb-public-http",
            "Public HTTP boundary",
            "flow-public-http",
        ));
    }
    for (kind, boundary) in optional_trust_boundaries() {
        if has_surface_kind(surfaces, kind) {
            boundaries.push(boundary);
        }
    }
    boundaries
}

fn has_public_http_surface(surfaces: &[AttackSurface]) -> bool {
    surfaces
        .iter()
        .any(|surface| surface.boundary.as_deref() == Some("public_http"))
}

fn has_surface_kind(surfaces: &[AttackSurface], kind: AttackSurfaceKind) -> bool {
    surfaces.iter().any(|surface| surface.kind == kind)
}
