use super::super::common::*;
use super::super::*;

pub(super) fn inspect_spark_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = spark_route_method(lower, state) else {
        return;
    };
    let Some(route) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    add_route(
        source_file,
        framework.or(Some("Spark Java")),
        line_number,
        detail,
        method,
        &route,
        "jvm.spark-route",
        builder,
    );
}

fn spark_route_method(line: &str, state: &RouteScanState) -> Option<&'static str> {
    for (marker, method) in [
        ("spark.get(", "GET"),
        ("spark.post(", "POST"),
        ("spark.put(", "PUT"),
        ("spark.patch(", "PATCH"),
        ("spark.delete(", "DELETE"),
        ("spark.head(", "HEAD"),
        ("spark.options(", "OPTIONS"),
        ("spark.before(", "ANY"),
        ("spark.after(", "ANY"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    if state.spark_static_routes {
        return spark_static_route_method(line);
    }
    None
}

fn spark_static_route_method(line: &str) -> Option<&'static str> {
    route_method_call(line).or_else(|| spark_static_filter_method(line))
}

fn spark_static_filter_method(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    (trimmed.starts_with("before(") || trimmed.starts_with("after(")).then_some("ANY")
}
