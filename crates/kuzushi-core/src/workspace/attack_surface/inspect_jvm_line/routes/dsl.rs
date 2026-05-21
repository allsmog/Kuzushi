mod armeria;
mod helidon;
mod javalin;
mod jooby;
mod ktor;
mod ratpack;
mod spark;
mod stateful;
mod undertow;
mod vertx;

use super::common::RouteScanState;
use super::*;

#[derive(Clone, Copy)]
pub(super) struct DslRouteLine<'a> {
    pub(super) source_file: &'a InventorySourceFile,
    pub(super) framework: Option<&'a str>,
    pub(super) line_number: u32,
    pub(super) detail: &'a str,
    pub(super) lower: &'a str,
}

pub(super) fn inspect_dsl_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    let line = DslRouteLine {
        source_file,
        framework,
        line_number,
        detail,
        lower,
    };
    stateful::inspect_stateful_dsl_routes(line, state, builder);
    inspect_spark_route(line, state, builder);
}

fn inspect_spark_route(
    line: DslRouteLine<'_>,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    spark::inspect_spark_route_line(
        line.source_file,
        line.framework,
        line.line_number,
        line.detail,
        line.lower,
        state,
        builder,
    );
}
