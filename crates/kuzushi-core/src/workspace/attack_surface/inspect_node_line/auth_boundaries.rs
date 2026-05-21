use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    inspect_auth_boundary(inspection, builder);
    inspect_session_state(inspection, builder);
    inspect_request_trust_boundary(inspection, builder);
    inspect_tenant_isolation(inspection, builder);
}

fn inspect_auth_boundary(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
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

fn inspect_session_state(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    if line_has_session_state(&inspection.lower) {
        inspection.add_surface(
            builder,
            AttackSurfaceKind::SessionStateBoundary,
            "Session state boundary",
            None,
            None,
            Some("session_state"),
            "node.session-state",
        );
    }
}

fn inspect_request_trust_boundary(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if line_has_request_trust_boundary(&inspection.lower) {
        inspection.add_surface(
            builder,
            AttackSurfaceKind::RequestTrustBoundary,
            "Request trust boundary",
            None,
            None,
            Some("request_trust"),
            "node.request-trust",
        );
    }
}

fn inspect_tenant_isolation(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if line_has_tenant_isolation(&inspection.lower) {
        inspection.add_surface(
            builder,
            AttackSurfaceKind::TenantIsolationBoundary,
            "Tenant isolation boundary",
            None,
            None,
            Some("tenant_isolation"),
            "node.tenant-isolation",
        );
    }
}

fn line_has_session_state(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            "express-session",
            "cookie-session",
            "request.cookies",
            "req.session",
            "res.cookie",
            "session(",
            "jwt.sign",
            "jwt.verify",
            "passport.session",
        ],
    )
}

fn line_has_request_trust_boundary(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            "csrf",
            "csurf",
            "cors(",
            "sameSite",
            "samesite",
            "access-control-allow-origin",
        ],
    )
}

fn line_has_tenant_isolation(lower: &str) -> bool {
    line_has_tenant_reference(lower)
        && line_contains_any(
            lower,
            &[
                "where",
                "filter",
                "authorize",
                "scope",
                "require",
                "check",
                "assert",
                "validate",
                "req.",
                "user.",
            ],
        )
}

fn line_has_tenant_reference(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            "tenantid",
            "tenant_id",
            "tenant.id",
            "organizationid",
            "organization_id",
            "orgid",
            "org_id",
            "workspaceid",
            "workspace_id",
            "accountid",
            "account_id",
            "currentteam",
            "current_team",
            "teamid",
            "team_id",
            "team.id",
        ],
    )
}
