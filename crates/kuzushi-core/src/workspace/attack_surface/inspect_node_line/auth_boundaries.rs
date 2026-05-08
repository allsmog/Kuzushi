use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    if is_route_line(&inspection.lower) && line_has_auth_guard(&inspection.lower) {
        let route = inspection.route();
        inspection.add_surface(
            builder,
            AttackSurfaceKind::AuthBoundary,
            "Route auth boundary",
            route.method.as_deref(),
            route.path.as_deref(),
            Some("auth_guard"),
            "node.express.auth-route",
        );
    } else if line_has_auth_guard(&inspection.lower) {
        inspection.add_surface(
            builder,
            AttackSurfaceKind::AuthBoundary,
            "Authentication or authorization guard",
            None,
            None,
            Some("auth_guard"),
            "node.auth-guard",
        );
    }
}
