use super::*;

pub(crate) fn inspect_go_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_go_import_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    for detector in GO_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

fn is_go_import_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("package ")
        || trimmed.starts_with("import ")
        || trimmed.starts_with('"')
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
        needles: &[
            "csrf",
            "cors.",
            "alloworigins",
            "samesite",
            "access-control-allow-origin",
            "r.header.get(",
        ],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::TenantIsolationBoundary,
        title: "Tenant isolation boundary",
        boundary: "tenant_isolation",
        detector: "go.tenant-isolation",
        needles: &[
            "accountid",
            "currentteam",
            "organizationid",
            "orgid",
            "teamid",
            "tenant_id",
            "tenantid",
            "workspaceid",
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
        kind: AttackSurfaceKind::FileUploadParsePath,
        title: "File upload or multipart parser",
        boundary: "file_upload",
        detector: "go.file-upload",
        needles: &[
            "parsemultipartform(",
            "formfile(",
            "multipart.reader",
            "multipart.newreader",
        ],
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
        kind: AttackSurfaceKind::RpcHandler,
        title: "gRPC handler",
        boundary: "rpc_handler",
        detector: "go.grpc-handler",
        needles: &["grpc.newserver(", "grpcserver("],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Command execution boundary",
        boundary: "process_execution",
        detector: "go.command-exec",
        needles: &["exec.command(", "os.startprocess("],
    },
    GoLineDetector {
        kind: AttackSurfaceKind::BackgroundJob,
        title: "Background job or queue consumer",
        boundary: "async_job",
        detector: "go.background-job",
        needles: &[
            "cron.addfunc(",
            "readmessage(",
            "channel.consume(",
            "receivemessage(",
            "subscription.receive(",
            "nats.subscribe(",
            "handlemux.handlefunc(",
            "asynq.handlerfunc(",
            "router.addhandler(",
        ],
    },
];
