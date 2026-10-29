//! PoC data layer: in-memory mirror of the threat-model store (real or
//! demo), simulated commits, demo documents and the `--seed` fixture writer.

use anyhow::{Context, Result};
use kuzushi_core::capabilities::{load_threat_model_manifest, load_threat_model_revision};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ───────────────────────────── data ─────────────────────────────

#[derive(Clone)]
pub(crate) struct Rev {
    pub(crate) id: String,
    pub(crate) sha: String,
    pub(crate) created_at: u64,
    pub(crate) source: String,
    pub(crate) run_id: Option<String>,
    pub(crate) verification: Option<String>,
    pub(crate) parent: Option<String>,
    /// Revision this one was derived from (`source_revision_id` in the real
    /// store). Differs from `parent` after a discard/regenerate rollback.
    pub(crate) base: Option<String>,
    pub(crate) simulated: bool,
    pub(crate) document: Value,
}

#[derive(Clone)]
pub(crate) struct Lineage {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) methodology: String,
    pub(crate) scope: String,
    /// Newest first.
    pub(crate) revisions: Vec<Rev>,
}

#[derive(Clone, PartialEq)]
pub(crate) struct RevRef {
    pub(crate) lineage: usize,
    pub(crate) rev: String,
}

pub(crate) struct Store {
    pub(crate) origin: String,
    /// Names the modeled system in the real Summary widget.
    pub(crate) target: PathBuf,
    pub(crate) lineages: Vec<Lineage>,
    pub(crate) active: Option<RevRef>,
}

impl Store {
    pub(crate) fn rev(&self, r: &RevRef) -> Option<&Rev> {
        self.lineages.get(r.lineage)?.revisions.iter().find(|x| x.id == r.rev)
    }
    pub(crate) fn label(&self, r: &RevRef) -> String {
        format!("{} {}", self.lineages[r.lineage].label, self.vlabel(r))
    }
    /// `v<n>`, counting from the lineage's first revision.
    pub(crate) fn vlabel(&self, r: &RevRef) -> String {
        let revs = &self.lineages[r.lineage].revisions;
        let n = revs.iter().position(|x| x.id == r.rev).map(|i| revs.len() - i).unwrap_or(0);
        format!("v{n}")
    }
    /// The next-older revision in the same lineage.
    pub(crate) fn previous(&self, r: &RevRef) -> Option<RevRef> {
        let revs = &self.lineages[r.lineage].revisions;
        let i = revs.iter().position(|x| x.id == r.rev)?;
        let known = |id: &Option<String>| id.clone().filter(|p| revs.iter().any(|x| &x.id == p));
        known(&revs[i].base).or_else(|| known(&revs[i].parent)).or_else(|| revs.get(i + 1).map(|p| p.id.clone())).map(|rev| RevRef { lineage: r.lineage, rev })
    }
    /// Append a new revision at the head of a lineage (simulated commit).
    pub(crate) fn commit(&mut self, lineage: usize, source: &str, document: Value) -> RevRef {
        let parent = self.lineages[lineage].revisions.first().map(|r| r.id.clone());
        let base = self.active.as_ref().filter(|a| a.lineage == lineage).map(|a| a.rev.clone());
        let n = self.lineages.iter().map(|l| l.revisions.len()).sum::<usize>();
        let id = format!("tmr_sim-{n:04}");
        let rev = Rev {
            id: id.clone(),
            sha: format!("sha256:sim-{n:04}"),
            created_at: now(),
            source: source.to_string(),
            run_id: Some(format!("tool-sim-{n}")),
            verification: None,
            parent,
            base,
            simulated: true,
            document,
        };
        self.lineages[lineage].revisions.insert(0, rev);
        RevRef { lineage, rev: id }
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub(crate) fn short(id: &str) -> String {
    let body = id.split_once('_').map(|(_, b)| b).unwrap_or(id);
    let body = body.strip_prefix("sha256:").unwrap_or(body);
    body.chars().take(8).collect()
}

pub(crate) fn age(secs: u64) -> String {
    let a = now().saturating_sub(secs);
    match a {
        0..=59 => format!("{a}s ago"),
        60..=3599 => format!("{}m ago", a / 60),
        3600..=86399 => format!("{}h ago", a / 3600),
        _ => format!("{}d ago", a / 86400),
    }
}

// ───────────────────────── real store load ─────────────────────────

pub(crate) fn load_real(root: &PathBuf) -> Result<Store> {
    let manifest = load_threat_model_manifest(root)?
        .with_context(|| format!("no threat-model store under {}", root.display()))?;
    let mut lineages = Vec::new();
    for model in &manifest.models {
        let mut revisions = Vec::new();
        for meta in &model.revisions {
            let doc = load_threat_model_revision(root, &model.model_id, Some(&meta.revision_id))
                .map(|m| m.document)
                .unwrap_or_else(|e| json!({ "loadError": format!("{e:#}") }));
            revisions.push(Rev {
                id: meta.revision_id.as_str().to_string(),
                sha: meta.sha256.clone(),
                created_at: meta.created_at.parse().unwrap_or(0),
                source: format!("{:?}", meta.source),
                run_id: meta.run_id.clone(),
                verification: meta.verification.as_ref().map(|v| v.verdict.clone()),
                parent: meta.parent_revision_id.as_ref().map(|p| p.as_str().to_string()),
                base: meta.source_revision_id.as_ref().map(|p| p.as_str().to_string()),
                simulated: false,
                document: doc,
            });
        }
        // Manifest order is commit order; reverse it, then a stable sort keeps
        // same-second commits newest first.
        revisions.reverse();
        revisions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        lineages.push(Lineage {
            id: model.model_id.as_str().to_string(),
            label: model.label.clone(),
            methodology: model.methodology.clone(),
            scope: model.scope.rel_path.display().to_string(),
            revisions,
        });
    }
    let active = manifest.active.as_ref().and_then(|a| {
        let lineage = lineages.iter().position(|l| l.id == a.model_id.as_str())?;
        Some(RevRef { lineage, rev: a.revision_id.as_str().to_string() })
    });
    Ok(Store { origin: root.display().to_string(), target: root.clone(), lineages, active })
}

// ─────────────────────────── demo data ───────────────────────────

#[allow(clippy::too_many_arguments)]
pub(crate) fn threat(id: &str, title: &str, impact: &str, likelihood: &str, actor: &str, surface: &str, asset: &str, els: &[&str]) -> Value {
    json!({
        "stableId": format!("st-{id}"), "id": id, "displayId": id, "title": title,
        "actor": actor, "surface": surface, "asset": asset,
        "impact": impact, "likelihood": likelihood, "status": "unmitigated",
        "existingMitigations": [], "evidence": [], "relatedCWEs": [], "targetElementIds": els,
    })
}

/// Demo component catalog: id → (name, type, trust zone, purpose).
pub(crate) fn node_meta(id: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match id {
        "browser" => ("Web browser", "external-entity", "internet", "Customers browse and pay over HTTPS"),
        "api" => ("API server", "process", "application", "Serves the storefront REST API"),
        "auth" => ("Auth service", "process", "application", "Issues and validates session tokens"),
        "db" => ("Postgres", "data-store", "data", "Stores accounts, orders and payments"),
        "admin" => ("Admin console", "process", "internal", "Staff manage accounts and refunds"),
        "logs" => ("Log pipeline", "data-store", "internal", "Collects request and audit logs"),
        "webhooks" => ("Webhook fetcher", "process", "application", "Fetches partner-supplied webhook URLs"),
        "queue" => ("Job queue", "data-store", "data", "Hands async payment jobs to workers"),
        _ => ("Callback handler", "process", "application", "Completes OAuth sign-in redirects"),
    }
}

pub(crate) fn node_json(id: &str) -> Value {
    let (name, kind, zone, purpose) = node_meta(id);
    json!({"id": id, "name": name, "type": kind, "trustZone": zone, "purpose": purpose, "description": purpose})
}

pub(crate) fn flow_json(id: &str) -> Value {
    let (src, dst) = id.split_once("->").unwrap_or((id, id));
    let label = match id {
        "browser->api" => "HTTPS requests with session cookie",
        "api->db" => "SQL queries",
        "api->auth" => "token validation",
        "admin->db" => "account and refund updates",
        "api->logs" => "request logs",
        "api->webhooks" => "partner webhook URLs",
        "api->queue" => "payment jobs",
        _ => "OAuth callback",
    };
    let mut flow = json!({"id": id, "sourceId": src, "targetId": dst, "description": label});
    if id == "browser->api" {
        flow["trustBoundaryIds"] = json!(["internet-edge"]);
    }
    flow
}

pub(crate) fn doc(methodology: &str, threats: Vec<Value>, nodes: &[&str], flows: &[&str], cov: (u64, u64)) -> Value {
    json!({
        "methodology": methodology,
        "systemContext": "Demo storefront: customers browse and pay through a REST API backed by Postgres; staff use an internal admin console.",
        "assets": [
            {"id": "A-accounts", "asset": "customer records", "description": "accounts, addresses and order history", "sensitivity": "high", "targetElementIds": ["db"]},
            {"id": "A-payments", "asset": "payments", "description": "payment intents and refunds", "sensitivity": "critical", "targetElementIds": ["db"]},
            {"id": "A-sessions", "asset": "session tokens", "description": "bearer cookies for signed-in users", "sensitivity": "high", "targetElementIds": ["auth"]},
        ],
        "attackSurface": {"entryPoints": [
            {"id": "EP-search", "name": "GET /search", "description": "public product search", "trustZone": "internet → application", "reachableAssets": "customer records", "targetElementIds": ["api"]},
            {"id": "EP-login", "name": "POST /login", "description": "password sign-in", "trustZone": "internet → application", "reachableAssets": "session tokens", "targetElementIds": ["auth"]},
        ]},
        "threats": threats,
        "deprioritized": [{"entryPoint": "GET /healthz", "reason": "static response, no asset reach"}],
        "openQuestions": [{"question": "Is the admin console reachable outside the VPN?"}],
        "provenance": {"pipeline": "staged", "builtAtMs": now() * 1000, "revision": "4f1c2ab", "revisionDirty": false, "sourceLabels": ["context", "source-code", "entry-points"]},
        "recommendedMitigations": [
            {"mitigation": "parameterize /search queries", "threatIds": ["T-1"], "closesClass": "yes", "effort": "S"},
            {"mitigation": "require MFA for the admin console", "threatIds": ["T-4"], "closesClass": "yes", "effort": "M"},
        ],
        "dfd": {
            "nodes": nodes.iter().map(|n| node_json(n)).collect::<Vec<_>>(),
            "flows": flows.iter().map(|f| flow_json(f)).collect::<Vec<_>>(),
            "trustBoundaries": [{
                "id": "internet-edge", "name": "Internet edge",
                "innerZone": "application", "outerZone": "internet",
                "crossingFlowIds": ["browser->api"],
            }],
        },
        "coverage": {"entryPointsConsidered": cov.0, "entryPointsCovered": cov.1},
    })
}

pub(crate) fn demo_threats_v1() -> Vec<Value> {
    vec![
        threat("T-1", "SQL injection in /search query builder", "high", "likely", "remote_unauth", "GET /search", "customer records", &["api"]),
        threat("T-2", "Session token leaked in access logs", "medium", "possible", "insider", "request logging", "session tokens", &["api", "logs"]),
        threat("T-3", "Missing rate limit on /login", "medium", "likely", "remote_unauth", "POST /login", "session tokens", &["auth"]),
        threat("T-4", "Admin panel reachable without MFA", "high", "possible", "remote_auth", "admin console", "payments", &["admin"]),
    ]
}

pub(crate) fn demo_store() -> Store {
    let t = now();
    let nodes1 = ["browser", "api", "auth", "db", "admin", "logs"];
    let flows1 = ["browser->api", "api->db", "api->auth", "admin->db", "api->logs"];
    let v1 = doc("stride", demo_threats_v1(), &nodes1, &flows1, (12, 8));
    let mut v2 = v1.clone();
    v2["threats"][1]["status"] = json!("mitigated");
    v2["threats"][1]["existingMitigations"] = json!(["log scrubber redacts session cookies"]);
    let mut t3 = demo_threats_v1();
    t3[0]["impact"] = json!("critical");
    t3[1] = v2["threats"][1].clone();
    t3.remove(2);
    t3.push(threat("T-5", "SSRF via webhook URL fetcher", "high", "likely", "remote_auth", "POST /webhooks", "internal network", &["webhooks"]));
    t3.push(threat("T-6", "Unsigned job payloads on worker queue", "medium", "rare", "internal_service", "job queue", "payments", &["queue"]));
    let nodes3 = ["browser", "api", "auth", "db", "admin", "logs", "webhooks", "queue"];
    let flows3 = ["browser->api", "api->db", "api->auth", "admin->db", "api->logs", "api->webhooks", "api->queue"];
    let mut v3 = doc("stride", t3, &nodes3, &flows3, (14, 12));
    v3["recommendedMitigations"].as_array_mut().unwrap().push(json!(
        {"mitigation": "allow-list partner webhook hosts", "threatIds": ["T-5"], "closesClass": "yes", "effort": "S"}
    ));
    v3["openQuestions"].as_array_mut().unwrap().push(json!({"question": "Do queue workers verify job signatures?"}));
    let pasta = doc(
        "pasta",
        vec![
            threat("P-1", "Account takeover via credential stuffing", "high", "likely", "remote_unauth", "POST /login", "session tokens", &["auth"]),
            threat("P-2", "Payment tamper through replayed webhook", "critical", "possible", "remote_auth", "POST /webhooks", "payments", &["webhooks"]),
        ],
        &nodes3,
        &flows3,
        (14, 9),
    );
    let rev = |id: &str, age_s: u64, source: &str, verif: Option<&str>, parent: Option<&str>, d: &Value| Rev {
        id: format!("tmr_{id}"),
        sha: format!("sha256:{id}{}", "0".repeat(40)),
        created_at: t - age_s,
        source: source.into(),
        run_id: Some(format!("tool-{}", t - age_s)),
        verification: verif.map(str::to_string),
        parent: parent.map(|p| format!("tmr_{p}")),
        base: None,
        simulated: false,
        document: d.clone(),
    };
    let stride = Lineage {
        id: "tm_5a1d2c9e7f00".into(),
        label: "root".into(),
        methodology: "stride".into(),
        scope: ".".into(),
        revisions: vec![
            rev("c3a9f1e0aa01", 3600, "Refine", Some("stale"), Some("b71e44d0aa01"), &v3),
            rev("b71e44d0aa01", 86_400 * 2, "Verify", Some("verified"), Some("a0f3b2c1aa01"), &v2),
            rev("a0f3b2c1aa01", 86_400 * 3, "Build", None, None, &v1),
        ],
    };
    let pasta_l = Lineage {
        id: "tm_9e8d7c6b5a00".into(),
        label: "root (pasta variant)".into(),
        methodology: "pasta".into(),
        scope: ".".into(),
        revisions: vec![rev("d4e5f6a7aa01", 86_400, "Build", Some("verified"), None, &pasta)],
    };
    Store {
        origin: "demo data (in-memory)".into(),
        target: PathBuf::from("demo-storefront"),
        lineages: vec![stride, pasta_l],
        active: Some(RevRef { lineage: 0, rev: "tmr_c3a9f1e0aa01".into() }),
    }
}

/// Derive a plausible next document for simulated builds.
pub(crate) fn evolve(document: &Value, fresh_ids: bool, n: usize) -> Value {
    let mut d = document.clone();
    if let Some(threats) = d.get_mut("threats").and_then(Value::as_array_mut) {
        if let Some(first) = threats.first_mut() {
            first["status"] = json!("mitigated");
        }
        threats.push(threat(
            &format!("T-{}", 10 + n),
            &format!("Open redirect on /callback (simulated run #{n})"),
            "medium",
            "possible",
            "remote_unauth",
            "GET /callback",
            "session tokens",
            &["api"],
        ));
        if fresh_ids {
            for (i, t) in threats.iter_mut().enumerate() {
                t["stableId"] = json!(format!("st-fresh{n}-{i}"));
            }
        }
    }
    if let Some(nodes) = d.pointer_mut("/dfd/nodes").and_then(Value::as_array_mut) {
        nodes.push(node_json(&format!("callback-{n}")));
    }
    if let Some(flows) = d.pointer_mut("/dfd/flows").and_then(Value::as_array_mut) {
        flows.push(flow_json(&format!("api->callback-{n}")));
    }
    d
}

pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    format!("{}…", text.chars().take(max).collect::<String>())
}

pub(crate) fn file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

/// Parse a drag-and-drop paste: macOS Terminal escapes spaces (`\ `), iTerm
/// and others may quote or send `file://` URIs; several files arrive
/// space- or newline-separated. Only tokens that exist on disk count.
pub(crate) fn dropped_paths(text: &str) -> Vec<PathBuf> {
    let mut tokens = Vec::new();
    let (mut cur, mut quote, mut chars) = (String::new(), None::<char>, text.trim().chars().peekable());
    while let Some(c) = chars.next() {
        match (c, quote) {
            ('\\', _) => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ('\'' | '"', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            (w, None) if w.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
        .into_iter()
        .map(|t| t.strip_prefix("file://").map(str::to_string).unwrap_or(t))
        .map(|t| match t.strip_prefix("~/") {
            Some(rest) => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(rest)).unwrap_or_else(|| PathBuf::from(&t)),
            None => PathBuf::from(t),
        })
        .filter(|p| p.exists())
        .collect()
}

// ──────────────────── --seed: build a real fixture store ────────────────────

/// Commit the demo revisions (oldest first) through the real store API so
/// `--target` can be exercised against genuine `.kuzushi/threat-models/`.
pub(crate) fn seed_real_store(dir: &PathBuf) -> Result<()> {
    use kuzushi_core::capabilities::{
        commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
    };
    std::fs::create_dir_all(dir)?;
    let scope = ScopeRef {
        scope_id: "root".into(),
        rel_path: PathBuf::from("."),
        project_model_sha256: "poc-fixture".into(),
        target_revision: "unavailable".into(),
    };
    let demo = demo_store();
    for lineage in &demo.lineages {
        let mut model_id = None;
        for rev in lineage.revisions.iter().rev() {
            let mut document = rev.document.clone();
            document["version"] = json!("1");
            document["summary"] = json!({ "text": format!("PoC fixture · {}", rev.source) });
            let source = match rev.source.as_str() {
                "Verify" => ThreatModelRevisionSource::Verify,
                "Refine" => ThreatModelRevisionSource::Refine,
                _ => ThreatModelRevisionSource::Build,
            };
            let result = commit_threat_model_revision(
                dir,
                &document,
                ThreatModelCommit {
                    model_id: model_id.clone(),
                    new_model: false,
                    label: lineage.label.clone(),
                    scope: scope.clone(),
                    methodology: lineage.methodology.clone(),
                    source,
                    source_revision_id: None,
                    run_id: rev.run_id.clone(),
                    activate: None,
                    actor: "threat-revisions-poc".into(),
                },
            )
            .with_context(|| format!("committing {} {}", lineage.label, rev.source))?;
            println!(
                "committed {} {} → {}@{} (activated: {})",
                lineage.label, rev.source, result.model_ref.model_id, result.model_ref.revision_id, result.activated
            );
            model_id = Some(result.model_ref.model_id);
        }
    }
    Ok(())
}

