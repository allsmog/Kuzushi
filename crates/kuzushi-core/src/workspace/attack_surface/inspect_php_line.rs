use super::*;

pub(crate) fn inspect_php_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_php_import_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    add_laravel_route(
        source_file,
        framework,
        line_number,
        &detail,
        &lower,
        builder,
    );
    for detector in PHP_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

fn is_php_import_line(line: &str) -> bool {
    let trimmed = line.trim_start().trim_start_matches("<?php").trim_start();
    trimmed.starts_with("use ")
        || trimmed.starts_with("require ")
        || trimmed.starts_with("include ")
}

fn add_laravel_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    if let Some((method, route)) = laravel_match_route(detail, lower) {
        add_laravel_route_surface(
            source_file,
            framework,
            line_number,
            detail,
            method,
            &route,
            builder,
        );
        return;
    }
    let Some((method, marker)) = laravel_route_method(lower) else {
        return;
    };
    let Some(route) = extract_quoted_after_marker_case_insensitive(detail, marker)
        .filter(|route| backend_route_path(route))
    else {
        return;
    };
    add_laravel_route_surface(
        source_file,
        framework,
        line_number,
        detail,
        method,
        &route,
        builder,
    );
}

fn add_laravel_route_surface(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    method: &str,
    route: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework.or(Some("Laravel")),
        line_number,
        &format!("{method} {route}"),
        detail,
        Some(method),
        Some(route),
        Some("public_http"),
        json!({ "source": "source_line", "detector": "php.laravel-route" }),
    ));
}

fn laravel_match_route(line: &str, lower: &str) -> Option<(&'static str, String)> {
    let marker = "route::match(";
    let start = lower.find(marker)? + marker.len();
    let arguments = &line[start..];
    let method = laravel_match_method(&arguments.to_ascii_lowercase())?;
    let route_start = arguments.find(']')? + 1;
    let route = extract_first_quoted(&arguments[route_start..])
        .filter(|route| backend_route_path(route))?;
    Some((method, route))
}

fn laravel_match_method(arguments: &str) -> Option<&'static str> {
    for (needle, method) in [
        ("'get'", "GET"),
        ("\"get\"", "GET"),
        ("'post'", "POST"),
        ("\"post\"", "POST"),
        ("'put'", "PUT"),
        ("\"put\"", "PUT"),
        ("'patch'", "PATCH"),
        ("\"patch\"", "PATCH"),
        ("'delete'", "DELETE"),
        ("\"delete\"", "DELETE"),
    ] {
        if arguments.contains(needle) {
            return Some(method);
        }
    }
    None
}

fn laravel_route_method(line: &str) -> Option<(&'static str, &'static str)> {
    for (marker, method) in [
        ("route::get(", "GET"),
        ("route::post(", "POST"),
        ("route::put(", "PUT"),
        ("route::patch(", "PATCH"),
        ("route::delete(", "DELETE"),
        ("route::any(", "ANY"),
    ] {
        if line.contains(marker) {
            return Some((method, marker));
        }
    }
    None
}

fn backend_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

struct PhpLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl PhpLineDetector {
    fn matches(&self, line: &str) -> bool {
        line_contains_any(line, self.needles)
    }

    fn surface(
        &self,
        source_file: &InventorySourceFile,
        framework: Option<&str>,
        line_number: u32,
        detail: &str,
    ) -> AttackSurfaceDraft {
        surface(
            self.kind,
            source_file,
            framework,
            line_number,
            self.title,
            detail,
            None,
            None,
            Some(self.boundary),
            json!({ "source": "source_line", "detector": self.detector }),
        )
    }
}

const PHP_LINE_DETECTORS: &[PhpLineDetector] = &[
    PhpLineDetector {
        kind: AttackSurfaceKind::AuthBoundary,
        title: "Authentication or authorization guard",
        boundary: "auth_guard",
        detector: "php.auth-guard",
        needles: &[
            "auth::",
            "auth()->",
            "$this->authorize",
            "gate::authorize",
            "middleware('auth",
        ],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::SessionStateBoundary,
        title: "Session state boundary",
        boundary: "session_state",
        detector: "php.session-state",
        needles: &[
            "session([",
            "session()->",
            "$_session",
            "cookie(",
            "jwtauth::",
        ],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::RequestTrustBoundary,
        title: "Request trust boundary",
        boundary: "request_trust",
        detector: "php.request-trust",
        needles: &[
            "$request->header",
            "csrf",
            "cors",
            "header(",
            "samesite",
            "verifycsrftoken",
        ],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::TenantIsolationBoundary,
        title: "Tenant isolation boundary",
        boundary: "tenant_isolation",
        detector: "php.tenant-isolation",
        needles: &[
            "account_id",
            "currentteam",
            "current_team",
            "organization_id",
            "team_id",
            "tenant_id",
            "tenantid",
            "workspace_id",
        ],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "php.deserialization",
        needles: &["unserialize(", "yaml_parse(", "json_decode("],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::FileUploadParsePath,
        title: "File upload or multipart parser",
        boundary: "file_upload",
        detector: "php.file-upload",
        needles: &[
            "hasfile(",
            "->file(",
            "->files->get(",
            "request->files",
            "uploadedfile",
            "$_files",
            "storeas(",
            "store(",
        ],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::DbQueryBoundary,
        title: "Database query boundary",
        boundary: "data_store",
        detector: "php.db-query",
        needles: &["db::select", "db::statement", "->where(", "->raw("],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::ExternalServiceClient,
        title: "External service client",
        boundary: "external_service",
        detector: "php.external-client",
        needles: &["http::", "guzzlehttp", "curl_exec", "file_get_contents("],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "php.command-exec",
        needles: &["shell_exec(", "exec(", "system(", "proc_open(", "passthru("],
    },
    PhpLineDetector {
        kind: AttackSurfaceKind::BackgroundJob,
        title: "Background job or queue consumer",
        boundary: "async_job",
        detector: "php.background-job",
        needles: &[
            "asmessagehandler",
            "messagehandlerinterface",
            "shouldqueue",
            "dispatch(",
            "queue::push",
            "bus::dispatch",
        ],
    },
];
