mod jaxrs;
mod micronaut;
mod servlet;
mod websocket;

use super::common::RouteScanState;
use super::*;

pub(super) fn inspect_annotation_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    servlet::emit_servlet_route(source_file, framework, line_number, detail, lower, builder);
    websocket::emit_websocket_route(source_file, framework, line_number, detail, lower, builder);
    micronaut::inspect_micronaut_route_line(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
    jaxrs::inspect_jaxrs_route_line(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}
