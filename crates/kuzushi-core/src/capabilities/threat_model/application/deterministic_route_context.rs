use crate::attack_surface::{line_contains_any, AttackSurface, AttackSurfaceKind};

pub(super) fn credential_flow_input(surface: &AttackSurface) -> Option<String> {
    (route_matches(surface, CREDENTIAL_ROUTE_MARKERS)
        || route_matches(surface, SECRET_ROUTE_MARKERS))
    .then(|| surface.title.clone())
}

pub(super) fn file_ingest_input(surface: &AttackSurface) -> Option<String> {
    (surface.kind == AttackSurfaceKind::FileUploadParsePath
        || route_matches(surface, FILE_INGEST_ROUTE_MARKERS))
    .then(|| surface.title.clone())
}

pub(super) fn data_egress_input(surface: &AttackSurface) -> Option<String> {
    route_matches(surface, DATA_EGRESS_ROUTE_MARKERS).then(|| surface.title.clone())
}

pub(super) fn callback_flow_input(surface: &AttackSurface) -> Option<String> {
    route_matches(surface, CALLBACK_ROUTE_MARKERS).then(|| surface.title.clone())
}

pub(super) fn authorization_flow_input(surface: &AttackSurface) -> Option<String> {
    (route_matches(surface, AUTHORIZATION_ROUTE_MARKERS)
        || route_matches(surface, TENANT_ROUTE_MARKERS))
    .then(|| surface.title.clone())
}

pub(super) fn cwe_for_surface(surface: &AttackSurface) -> Vec<&'static str> {
    let mut cwes = cwe_for_kind(surface.kind);
    cwes.extend(route_cwes(surface));
    cwes.sort();
    cwes.dedup();
    cwes
}

fn cwe_for_kind(kind: AttackSurfaceKind) -> Vec<&'static str> {
    match kind {
        AttackSurfaceKind::HttpRoute => vec!["CWE-20"],
        AttackSurfaceKind::RpcHandler => vec!["CWE-20"],
        AttackSurfaceKind::CommandExecutionBoundary => vec!["CWE-78"],
        AttackSurfaceKind::DbQueryBoundary => vec!["CWE-89"],
        AttackSurfaceKind::DeserializationPoint => vec!["CWE-502"],
        AttackSurfaceKind::FileUploadParsePath => vec!["CWE-434"],
        AttackSurfaceKind::BackgroundJob => vec!["CWE-400"],
        AttackSurfaceKind::ExternalServiceClient => vec!["CWE-918"],
        AttackSurfaceKind::CliEntrypoint => vec!["CWE-20"],
        AttackSurfaceKind::AuthBoundary => vec!["CWE-287"],
        AttackSurfaceKind::SessionStateBoundary => vec!["CWE-384"],
        AttackSurfaceKind::RequestTrustBoundary => vec!["CWE-352"],
        AttackSurfaceKind::TenantIsolationBoundary => vec!["CWE-639"],
    }
}

fn route_cwes(surface: &AttackSurface) -> Vec<&'static str> {
    let mut cwes = Vec::new();
    append_route_cwes(&mut cwes, surface, CREDENTIAL_ROUTE_MARKERS, &["CWE-640"]);
    append_route_cwes(&mut cwes, surface, SECRET_ROUTE_MARKERS, &["CWE-522"]);
    append_route_cwes(&mut cwes, surface, FILE_INGEST_ROUTE_MARKERS, &["CWE-434"]);
    append_route_cwes(&mut cwes, surface, DATA_EGRESS_ROUTE_MARKERS, &["CWE-200"]);
    append_route_cwes(&mut cwes, surface, CALLBACK_ROUTE_MARKERS, &["CWE-601", "CWE-918"]);
    append_route_cwes(&mut cwes, surface, AUTHORIZATION_ROUTE_MARKERS, &["CWE-862", "CWE-863"]);
    append_route_cwes(&mut cwes, surface, TENANT_ROUTE_MARKERS, &["CWE-639"]);
    cwes
}

fn append_route_cwes(
    cwes: &mut Vec<&'static str>,
    surface: &AttackSurface,
    markers: &[&str],
    additions: &[&'static str],
) {
    if route_matches(surface, markers) {
        cwes.extend(additions);
    }
}

fn route_matches(surface: &AttackSurface, markers: &[&str]) -> bool {
    surface
        .route
        .as_deref()
        .map(|route| line_contains_any(&route.to_ascii_lowercase(), markers))
        .unwrap_or(false)
}

const CREDENTIAL_ROUTE_MARKERS: &[&str] = &[
    "2fa",
    "account",
    "backup-code",
    "change-email",
    "credential",
    "credentials",
    "email-change",
    "email-verification",
    "identity",
    "login",
    "magic-link",
    "magiclink",
    "mfa",
    "oauth",
    "oidc",
    "otp",
    "passkey",
    "password",
    "recovery",
    "recovery-code",
    "saml",
    "signin",
    "signup",
    "sso",
    "token",
    "totp",
    "verify-email",
    "webauthn",
];
const SECRET_ROUTE_MARKERS: &[&str] = &["api-key", "apikey", "credential", "credentials", "secret"];
const FILE_INGEST_ROUTE_MARKERS: &[&str] = &[
    "archive", "avatar", "backup", "file", "import", "parse", "restore", "upload",
];
const DATA_EGRESS_ROUTE_MARKERS: &[&str] =
    &[
        "asset",
        "download",
        "export",
        "files/",
        "metrics",
        "prometheus",
        "static",
    ];
const CALLBACK_ROUTE_MARKERS: &[&str] = &[
    "callback",
    "connect",
    "federation",
    "oidc",
    "proxy",
    "redirect",
    "return-to",
    "return_to",
    "returnto",
    "return-url",
    "saml",
    "webhook",
];
const AUTHORIZATION_ROUTE_MARKERS: &[&str] = &[
    "admin",
    "billing",
    "impersonate",
    "invite",
    "invitation",
    "payment",
    "permission",
    "refund",
    "role",
    "scim",
    "subscription",
];
const TENANT_ROUTE_MARKERS: &[&str] = &[
    "account",
    "accounts",
    "org",
    "team",
    "teams",
    "tenant",
    "workspace",
];
