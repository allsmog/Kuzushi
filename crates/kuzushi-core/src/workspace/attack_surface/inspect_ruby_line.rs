use super::*;

pub(crate) fn inspect_ruby_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_ruby_import_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    add_rails_route(source_file, framework, line_number, &detail, &lower, builder);
    for detector in RUBY_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

fn is_ruby_import_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("require ") || trimmed.starts_with("require_relative ")
}

fn add_rails_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = rails_route_method(lower) else {
        return;
    };
    let Some(route) = extract_first_quoted(detail).filter(|route| backend_route_path(route)) else {
        return;
    };
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework.or(Some("Rails")),
        line_number,
        &format!("{method} {route}"),
        detail,
        Some(method),
        Some(&route),
        Some("public_http"),
        json!({ "source": "source_line", "detector": "ruby.rails-route" }),
    ));
}

fn rails_route_method(line: &str) -> Option<&'static str> {
    if line.trim_start().starts_with("match ") {
        return rails_match_via_method(line).or(Some("ANY"));
    }
    for (marker, method) in [
        ("get ", "GET"),
        ("post ", "POST"),
        ("put ", "PUT"),
        ("patch ", "PATCH"),
        ("delete ", "DELETE"),
    ] {
        if line.trim_start().starts_with(marker) {
            return Some(method);
        }
    }
    None
}

fn rails_match_via_method(line: &str) -> Option<&'static str> {
    for (needle, method) in [
        ("via: :get", "GET"),
        ("via: :post", "POST"),
        ("via: :put", "PUT"),
        ("via: :patch", "PATCH"),
        ("via: :delete", "DELETE"),
        ("via: 'get'", "GET"),
        ("via: 'post'", "POST"),
        ("via: 'put'", "PUT"),
        ("via: 'patch'", "PATCH"),
        ("via: 'delete'", "DELETE"),
        ("via: \"get\"", "GET"),
        ("via: \"post\"", "POST"),
        ("via: \"put\"", "PUT"),
        ("via: \"patch\"", "PATCH"),
        ("via: \"delete\"", "DELETE"),
    ] {
        if line.contains(needle) {
            return Some(method);
        }
    }
    None
}

fn backend_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

struct RubyLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl RubyLineDetector {
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

const RUBY_LINE_DETECTORS: &[RubyLineDetector] = &[
    RubyLineDetector {
        kind: AttackSurfaceKind::AuthBoundary,
        title: "Authentication or authorization guard",
        boundary: "auth_guard",
        detector: "ruby.auth-guard",
        needles: &["authenticate_user!", "authorize ", "pundit", "can?("],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::SessionStateBoundary,
        title: "Session state boundary",
        boundary: "session_state",
        detector: "ruby.session-state",
        needles: &["session[", "cookies[", "cookies.signed", "jwt.decode", "jwt.encode"],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::RequestTrustBoundary,
        title: "Request trust boundary",
        boundary: "request_trust",
        detector: "ruby.request-trust",
        needles: &[
            "headers[",
            "protect_from_forgery",
            "request.headers",
            "verify_authenticity_token",
            "rack::cors",
            "same_site",
        ],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::TenantIsolationBoundary,
        title: "Tenant isolation boundary",
        boundary: "tenant_isolation",
        detector: "ruby.tenant-isolation",
        needles: &[
            "account_id",
            "current_account",
            "current_organization",
            "current_tenant",
            "organization_id",
            "tenant_id",
            "tenantid",
            "workspace_id",
        ],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "ruby.deserialization",
        needles: &["yaml.load", "marshal.load", "json.parse"],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::FileUploadParsePath,
        title: "File upload or multipart parser",
        boundary: "file_upload",
        detector: "ruby.file-upload",
        needles: &[
            "has_one_attached",
            "has_many_attached",
            "activestorage",
            "params[:file]",
            "params[:upload]",
            "uploaded_file",
        ],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::DbQueryBoundary,
        title: "Database query boundary",
        boundary: "data_store",
        detector: "ruby.db-query",
        needles: &["connection.execute", "exec_query", "find_by_sql", ".where("],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::ExternalServiceClient,
        title: "External service client",
        boundary: "external_service",
        detector: "ruby.external-client",
        needles: &["net::http", "faraday.", "httparty.", "httpclient."],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "ruby.command-exec",
        needles: &["system(", "open3.", "io.popen", "%x["],
    },
    RubyLineDetector {
        kind: AttackSurfaceKind::BackgroundJob,
        title: "Background job or queue consumer",
        boundary: "async_job",
        detector: "ruby.background-job",
        needles: &[
            "sidekiq::job",
            "sidekiq::worker",
            "applicationjob",
            "perform_async",
            "queue_as ",
            "delayed::job",
            "karafka",
        ],
    },
];
