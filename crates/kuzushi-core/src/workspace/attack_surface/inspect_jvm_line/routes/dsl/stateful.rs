use super::super::common::RouteScanState;
use super::super::*;
use super::{armeria, helidon, javalin, jooby, ktor, ratpack, undertow, vertx, DslRouteLine};

type StatefulDslInspector = fn(
    &InventorySourceFile,
    Option<&str>,
    u32,
    &str,
    &str,
    &mut RouteScanState,
    &mut AttackSurfaceBuilder,
);

const STATEFUL_DSL_INSPECTORS: &[StatefulDslInspector] = &[
    javalin::inspect_javalin_route_line,
    jooby::inspect_jooby_route_line,
    ktor::inspect_ktor_route_line,
    vertx::inspect_vertx_route_line,
    armeria::inspect_armeria_route_line,
    helidon::inspect_helidon_route_line,
    ratpack::inspect_ratpack_route_line,
    undertow::inspect_undertow_route_line,
];

pub(super) fn inspect_stateful_dsl_routes(
    line: DslRouteLine<'_>,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    for inspector in STATEFUL_DSL_INSPECTORS {
        inspector(
            line.source_file,
            line.framework,
            line.line_number,
            line.detail,
            line.lower,
            state,
            builder,
        );
    }
}
