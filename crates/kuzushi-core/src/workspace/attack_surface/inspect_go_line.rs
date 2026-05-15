use super::*;

pub(crate) fn inspect_go_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    for detector in GO_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

struct GoLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl GoLineDetector {
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

const GO_LINE_DETECTORS: &[GoLineDetector] = &[
    GoLineDetector {
        kind: AttackSurfaceKind::AuthBoundary,
        title: "Authentication or authorization guard",
        boundary: "auth_guard",
        detector: "go.auth-guard",
        needles: &["authmiddleware", "requireuser", "authorize"],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::SessionStateBoundary,
        title: "Session state boundary",
        boundary: "session_state",
        detector: "go.session-state",
        needles: &[
            "sessions.get(",
            "session.get(",
            "setcookie(",
            "cookie(",
            "jwt.parse",
            "signedstring(",
        ],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::RequestTrustBoundary,
        title: "Request trust boundary",
        boundary: "request_trust",
        detector: "go.request-trust",
        needles: &["csrf", "cors.", "alloworigins", "samesite", "access-control-allow-origin"],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::TenantIsolationBoundary,
        title: "Tenant isolation boundary",
        boundary: "tenant_isolation",
        detector: "go.tenant-isolation",
        needles: &[
            "tenantid",
            "tenant_id",
            "organizationid",
            "orgid",
            "workspaceid",
            "accountid",
        ],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "go.deserialization",
        needles: &["json.newdecoder", "yaml.", "proto.unmarshal"],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::DbQueryBoundary,
        title: "Database query boundary",
        boundary: "data_store",
        detector: "go.db-query",
        needles: &[".query(", ".exec(", "db."],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::ExternalServiceClient,
        title: "External service client",
        boundary: "external_service",
        detector: "go.external-client",
        needles: &["http.get(", "http.post(", "http.newrequest(", ".do(req"],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "go.command-exec",
        needles: &["exec.command(", "os.startprocess("],
    },
];
