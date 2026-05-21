use super::super::common::*;
use super::super::*;

pub(super) fn emit_websocket_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    if !lower.contains("@serverendpoint") {
        return;
    }
    let Some(route) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    add_route(
        source_file,
        framework.or(Some("WebSocket")),
        line_number,
        detail,
        "ANY",
        &route,
        "jvm.websocket-route",
        builder,
    );
}
