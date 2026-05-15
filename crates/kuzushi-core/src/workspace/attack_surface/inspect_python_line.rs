use super::*;

pub(crate) fn inspect_python_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    for detector in PYTHON_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

struct PythonLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl PythonLineDetector {
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

const PYTHON_LINE_DETECTORS: &[PythonLineDetector] = &[
    PythonLineDetector {
        kind: AttackSurfaceKind::AuthBoundary,
        title: "Authentication or authorization guard",
        boundary: "auth_guard",
        detector: "python.auth-guard",
        needles: &["login_required", "permission_required"],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::SessionStateBoundary,
        title: "Session state boundary",
        boundary: "session_state",
        detector: "python.session-state",
        needles: &[
            "session[",
            "request.session",
            "flask.session",
            "set_cookie",
            "jwt.decode",
            "jwt.encode",
        ],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::RequestTrustBoundary,
        title: "Request trust boundary",
        boundary: "request_trust",
        detector: "python.request-trust",
        needles: &["csrf_protect", "csrf_exempt", "cors(", "samesite", "set_cookie"],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::TenantIsolationBoundary,
        title: "Tenant isolation boundary",
        boundary: "tenant_isolation",
        detector: "python.tenant-isolation",
        needles: &[
            "tenant_id",
            "tenantid",
            "organization_id",
            "org_id",
            "workspace_id",
            "account_id",
        ],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "python.deserialization",
        needles: &["pickle.loads", "yaml.load(", "json.loads("],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::DbQueryBoundary,
        title: "Database query boundary",
        boundary: "data_store",
        detector: "python.db-query",
        needles: &["cursor.execute", ".execute(", "session.execute("],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::ExternalServiceClient,
        title: "External service client",
        boundary: "external_service",
        detector: "python.external-client",
        needles: &["requests.", "httpx.", "aiohttp.", "urllib.request"],
    },
    PythonLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "python.command-exec",
        needles: &["shell=true", "subprocess.", "os.system("],
    },
];
