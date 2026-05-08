use super::prelude::*;
use super::*;

pub(crate) fn infer_http_technologies(
    headers: &BTreeMap<String, String>,
    body: &str,
) -> Vec<String> {
    let mut tech = BTreeSet::new();
    if let Some(server) = headers.get("server") {
        let lower = server.to_ascii_lowercase();
        for (needle, label) in [
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("cloudflare", "cloudflare"),
            ("express", "express"),
        ] {
            if lower.contains(needle) {
                tech.insert(label.to_string());
            }
        }
    }
    if let Some(powered_by) = headers.get("x-powered-by") {
        tech.insert(powered_by.trim().to_string());
    }
    let body_lower = body.to_ascii_lowercase();
    for (needle, label) in [
        ("wp-content", "wordpress"),
        ("_next/static", "next.js"),
        ("data-reactroot", "react"),
        ("<meta name=\"generator\" content=\"hugo", "hugo"),
    ] {
        if body_lower.contains(needle) {
            tech.insert(label.to_string());
        }
    }
    tech.into_iter().collect()
}

pub struct ReconWorkspaceStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: String,
}
