mod annotation;
mod common;
mod dsl;

use super::*;
use common::RouteScanState;

pub(crate) fn inspect_jvm_routes(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    text: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let mut state = RouteScanState {
        spark_static_routes: text
            .to_ascii_lowercase()
            .contains("import static spark.spark."),
        ..RouteScanState::default()
    };
    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        inspect_jvm_route_line(source_file, framework, line_number, line, &mut state, builder);
    }
}

fn inspect_jvm_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_jvm_import_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    dsl::inspect_dsl_route_line(source_file, framework, line_number, &detail, &lower, state, builder);
    annotation::inspect_annotation_route_line(
        source_file,
        framework,
        line_number,
        &detail,
        &lower,
        state,
        builder,
    );
}
