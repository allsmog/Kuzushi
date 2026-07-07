use super::*;

pub(crate) fn summarize_surfaces(surfaces: &[AttackSurface]) -> AttackSurfaceSummary {
    let mut by_kind = BTreeMap::new();
    let mut by_file = BTreeMap::new();
    for surface in surfaces {
        *by_kind
            .entry(surface.kind.as_str().to_string())
            .or_insert(0) += 1;
        *by_file.entry(surface.path.clone()).or_insert(0) += 1;
    }
    AttackSurfaceSummary {
        total: surfaces.len(),
        by_kind,
        by_file,
        high_risk: high_risk_count(surfaces),
        max_risk_score: max_risk_score(surfaces),
        by_risk_tier: risk_tier_counts(surfaces),
    }
}

fn high_risk_count(surfaces: &[AttackSurface]) -> usize {
    surfaces
        .iter()
        .filter(|surface| matches!(surface.risk.tier.as_str(), "critical" | "high"))
        .count()
}

fn max_risk_score(surfaces: &[AttackSurface]) -> u16 {
    surfaces
        .iter()
        .map(|surface| surface.risk.score)
        .max()
        .unwrap_or_default()
}

fn risk_tier_counts(surfaces: &[AttackSurface]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for surface in surfaces {
        *counts.entry(surface.risk.tier.clone()).or_insert(0) += 1;
    }
    counts
}

pub(crate) fn rank_attack_surfaces(mut surfaces: Vec<AttackSurface>) -> Vec<AttackSurface> {
    for surface in &mut surfaces {
        surface.risk = risk_for_surface(surface);
    }
    surfaces.sort_by(risk_order);
    for (index, surface) in surfaces.iter_mut().enumerate() {
        surface.risk.rank = index + 1;
    }
    surfaces
}

fn risk_for_surface(surface: &AttackSurface) -> AttackSurfaceRisk {
    let mut score = kind_base_score(surface.kind);
    let mut reasons = vec![format!("{} base exposure", surface.kind.as_str())];
    add_boundary_risk(surface, &mut score, &mut reasons);
    add_route_risk(surface, &mut score, &mut reasons);
    add_evidence_risk(surface, &mut score, &mut reasons);
    score = score.min(100);
    AttackSurfaceRisk {
        rank: 0,
        score,
        tier: risk_tier(score).to_string(),
        reasons,
    }
}

fn kind_base_score(kind: AttackSurfaceKind) -> u16 {
    match kind {
        AttackSurfaceKind::CommandExecutionBoundary => 90,
        AttackSurfaceKind::FileUploadParsePath => 82,
        AttackSurfaceKind::DeserializationPoint => 78,
        AttackSurfaceKind::DbQueryBoundary => 70,
        AttackSurfaceKind::TenantIsolationBoundary => 66,
        AttackSurfaceKind::AuthBoundary => 65,
        AttackSurfaceKind::RequestTrustBoundary => 64,
        AttackSurfaceKind::SessionStateBoundary => 62,
        AttackSurfaceKind::RpcHandler => 60,
        AttackSurfaceKind::ExternalServiceClient => 58,
        AttackSurfaceKind::HttpRoute => 50,
        AttackSurfaceKind::CliEntrypoint => 42,
        AttackSurfaceKind::BackgroundJob => 35,
    }
}

fn add_boundary_risk(surface: &AttackSurface, score: &mut u16, reasons: &mut Vec<String>) {
    if surface.boundary.as_deref() == Some("public_http") {
        *score += 15;
        reasons.push("crosses public HTTP boundary".to_string());
    }
}

fn add_route_risk(surface: &AttackSurface, score: &mut u16, reasons: &mut Vec<String>) {
    if mutating_method(surface.method.as_deref()) {
        *score += 10;
        reasons.push("mutating request method".to_string());
    }
    if route_contains(surface, AUTH_OR_ADMIN_ROUTE_MARKERS) {
        *score += 12;
        reasons.push("route touches auth or admin workflow".to_string());
    }
    if route_contains(surface, RICH_INPUT_ROUTE_MARKERS) {
        *score += 10;
        reasons.push("route accepts rich external input".to_string());
    }
}

const AUTH_OR_ADMIN_ROUTE_MARKERS: &[&str] = &[
    "account",
    "admin",
    "2fa",
    "api-key",
    "apikey",
    "backup-code",
    "billing",
    "change-email",
    "credential",
    "credentials",
    "csrf",
    "email-change",
    "email-verification",
    "login",
    "logout",
    "oidc",
    "passkey",
    "invite",
    "invitation",
    "impersonate",
    "mfa",
    "magic-link",
    "magiclink",
    "oauth",
    "org",
    "otp",
    "password",
    "payment",
    "permission",
    "recovery",
    "recovery-code",
    "refund",
    "role",
    "secret",
    "saml",
    "scim",
    "session",
    "signin",
    "signup",
    "sso",
    "subscription",
    "tenant",
    "token",
    "totp",
    "verify-email",
    "webauthn",
    "workspace",
];

const RICH_INPUT_ROUTE_MARKERS: &[&str] = &[
    "archive",
    "avatar",
    "backup",
    "callback",
    "connect",
    "download",
    "export",
    "federation",
    "file",
    "graphql",
    "import",
    "parse",
    "restore",
    "return-to",
    "return_to",
    "returnto",
    "return-url",
    "proxy",
    "realtime",
    "redirect",
    "socket",
    "subscription",
    "upload",
    "webhook",
    "websocket",
    "webauthn",
];

fn add_evidence_risk(surface: &AttackSurface, score: &mut u16, reasons: &mut Vec<String>) {
    let evidence = surface.evidence.to_ascii_lowercase();
    if line_contains_any(&evidence, REQUEST_CONTROLLED_EVIDENCE) {
        *score += 8;
        reasons.push("evidence references request-controlled data".to_string());
    }
}

const REQUEST_CONTROLLED_EVIDENCE: &[&str] = &[
    "$request->file",
    "request.args",
    "request.body",
    "request.cookies",
    "request.data",
    "request.cookies",
    "request.files",
    "request.form",
    "request.get",
    "request.get_json",
    "request.headers",
    "request.json",
    "request.meta",
    "request.post",
    "request.query_params",
    "request.query",
    "req.body",
    "req.cookies",
    "req.file",
    "req.files",
    "req.headers",
    "req.query",
    "cookies[",
    "cookies.signed",
    "cookies.get(",
    "params",
    "input",
    "tenant",
    "params[",
    "$request->cookie",
    "$request->input",
    "$_cookie",
    "$_files",
    "$_get",
    "$_post",
    "$_request",
    "@requestbody",
    "@requestparam",
    "@requestheader",
    "getparameter(",
    "getheader(",
    "org_id",
    "workspace",
    "r.body",
    "r.cookie(",
    "r.header.get(",
    "formvalue(",
    "url.query(",
    "postform",
    "header.get(",
    "headers.get(",
    "json<",
    "query<",
    "path<",
    "form<",
    "iformfile",
    "request.body",
    "request.form.files",
    "[frombody",
    "[fromform",
    "[fromheader",
    "[fromquery",
];

fn mutating_method(method: Option<&str>) -> bool {
    matches!(method, Some("POST" | "PUT" | "PATCH" | "DELETE"))
}

fn route_contains(surface: &AttackSurface, needles: &[&str]) -> bool {
    surface
        .route
        .as_deref()
        .map(|route| line_contains_any(&route.to_ascii_lowercase(), needles))
        .unwrap_or(false)
}

fn risk_tier(score: u16) -> &'static str {
    match score {
        90..=u16::MAX => "critical",
        75..=89 => "high",
        50..=74 => "medium",
        _ => "low",
    }
}

fn risk_order(left: &AttackSurface, right: &AttackSurface) -> std::cmp::Ordering {
    right
        .risk
        .score
        .cmp(&left.risk.score)
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.line.cmp(&right.line))
        .then_with(|| left.id.cmp(&right.id))
}

pub(crate) fn attack_surface_id(surface: &AttackSurface) -> String {
    let metadata = serde_json::to_string(&surface.metadata).unwrap_or_else(|_| "{}".to_string());
    let segments = [
        surface.kind.as_str(),
        &surface.path,
        &surface
            .line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &surface.language,
        surface.framework.as_deref().unwrap_or(""),
        &surface.title,
        &surface.evidence,
        surface.method.as_deref().unwrap_or(""),
        surface.route.as_deref().unwrap_or(""),
        surface.boundary.as_deref().unwrap_or(""),
        &metadata,
    ];
    let body = segments.join("\0");
    format!("AS-{}", &static_content_hash(&body)[..16])
}

pub(crate) fn language_from_path(path: &str) -> Option<&'static str> {
    let extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "rs" => Some("Rust"),
        "java" => Some("Java"),
        "kt" | "kts" => Some("Kotlin"),
        "cs" => Some("C#"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        _ => None,
    }
}

pub(crate) fn trim_detail(line: &str) -> String {
    line.trim().split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn line_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub(crate) fn extract_quoted_after_marker_case_insensitive(
    line: &str,
    marker: &str,
) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}

pub(crate) fn extract_first_quoted(value: &str) -> Option<String> {
    let (start, quote) = first_quote(value)?;
    quoted_body(value, start, quote).and_then(non_empty_quoted_value)
}

fn first_quote(value: &str) -> Option<(usize, char)> {
    value.char_indices().find(|(_, ch)| is_quote(*ch))
}

fn quoted_body(value: &str, start: usize, quote: char) -> Option<&str> {
    let body_start = start + quote.len_utf8();
    let body = &value[body_start..];
    let body_end = body.find(quote)?;
    Some(&body[..body_end])
}

fn non_empty_quoted_value(candidate: &str) -> Option<String> {
    if candidate.trim().is_empty() {
        return None;
    }
    Some(candidate.to_string())
}

fn is_quote(ch: char) -> bool {
    matches!(ch, '"' | '\'' | '`')
}
