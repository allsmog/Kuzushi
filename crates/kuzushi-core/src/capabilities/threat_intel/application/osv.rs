use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::process::Command;

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OsvPackageQuery {
    pub(crate) ecosystem: String,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OsvCandidate {
    pub(crate) id: String,
    pub(crate) summary: String,
    pub(crate) package: String,
    pub(crate) ecosystem: String,
    pub(crate) version: Option<String>,
}

impl OsvCandidate {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "summary": self.summary,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "source": "osv",
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct OsvQueryReport {
    pub(crate) candidates: Vec<OsvCandidate>,
    pub(crate) queried_packages: usize,
    pub(crate) failed_packages: Vec<String>,
}

pub(crate) fn query_osv_candidates(
    packages: &[OsvPackageQuery],
    max_per_package: usize,
    max_total: usize,
    fixtures: Option<&Value>,
) -> OsvQueryReport {
    let mut report = OsvQueryReport::default();
    let mut seen = BTreeSet::new();
    for package in packages {
        report.queried_packages += 1;
        let response = osv_response(package, fixtures);
        let Ok(response) = response else {
            report.failed_packages.push(package.name.clone());
            continue;
        };
        append_candidates(
            &mut report.candidates,
            &mut seen,
            package,
            &response,
            max_per_package,
            max_total,
        );
        if report.candidates.len() >= max_total {
            break;
        }
    }
    report
}

fn osv_response(package: &OsvPackageQuery, fixtures: Option<&Value>) -> Result<Value> {
    if let Some(fixtures) = fixtures {
        return fixture_response(fixtures, &package.name);
    }
    query_osv_package(package)
}

fn fixture_response(fixtures: &Value, package: &str) -> Result<Value> {
    let rows = fixtures.get(package).cloned().unwrap_or_else(|| json!([]));
    if rows.is_array() {
        return Ok(json!({"vulns": rows}));
    }
    anyhow::ensure!(
        rows.get("vulns").and_then(Value::as_array).is_some(),
        "OSV fixture for {package} must be an array or an object with vulns[]"
    );
    Ok(rows)
}

fn query_osv_package(package: &OsvPackageQuery) -> Result<Value> {
    let body = osv_query_body(package).to_string();
    let mut command = Command::new("curl");
    command
        .args([
            "-fsSL",
            "--max-time",
            "15",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
        ])
        .arg(body)
        .arg("--")
        .arg(OSV_QUERY_URL);
    let output = crate::bounded_subprocess::output(&mut command, "osv advisory query")?;
    anyhow::ensure!(
        output.status.success(),
        "OSV query failed for {}",
        package.name
    );
    serde_json::from_slice(&output.stdout).context("OSV query returned invalid JSON")
}

fn osv_query_body(package: &OsvPackageQuery) -> Value {
    let mut body = json!({
        "package": {
            "name": package.name,
            "ecosystem": package.ecosystem,
        }
    });
    if let Some(version) = &package.version {
        body["version"] = json!(version);
    }
    body
}

fn append_candidates(
    candidates: &mut Vec<OsvCandidate>,
    seen: &mut BTreeSet<String>,
    package: &OsvPackageQuery,
    response: &Value,
    max_per_package: usize,
    max_total: usize,
) {
    let Some(vulns) = response.get("vulns").and_then(Value::as_array) else {
        return;
    };
    for vuln in vulns.iter().take(max_per_package) {
        let Some(candidate) = candidate_from_vuln(package, vuln) else {
            continue;
        };
        if seen.insert(candidate.id.clone()) {
            candidates.push(candidate);
        }
        if candidates.len() >= max_total {
            break;
        }
    }
}

fn candidate_from_vuln(package: &OsvPackageQuery, vuln: &Value) -> Option<OsvCandidate> {
    Some(OsvCandidate {
        id: vuln.get("id")?.as_str()?.to_string(),
        summary: vuln
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        package: package.name.clone(),
        ecosystem: package.ecosystem.clone(),
        version: package.version.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_queries_are_bounded_and_deduplicate_ids() {
        let packages = vec![
            OsvPackageQuery {
                ecosystem: "Go".to_string(),
                name: "example.com/a".to_string(),
                version: Some("1.0.0".to_string()),
            },
            OsvPackageQuery {
                ecosystem: "Go".to_string(),
                name: "example.com/b".to_string(),
                version: None,
            },
        ];
        let fixtures = json!({
            "example.com/a": [
                {"id": "GO-2026-1", "summary": "first"},
                {"id": "GO-2026-2", "summary": "second"}
            ],
            "example.com/b": [
                {"id": "GO-2026-1", "summary": "duplicate"},
                {"id": "GO-2026-3", "summary": "third"}
            ]
        });

        let report = query_osv_candidates(&packages, 2, 2, Some(&fixtures));

        assert_eq!(report.queried_packages, 1);
        assert_eq!(report.candidates.len(), 2);
        assert_eq!(report.candidates[0].id, "GO-2026-1");
        assert_eq!(report.candidates[1].id, "GO-2026-2");
        assert!(report.failed_packages.is_empty());
    }

    #[test]
    fn malformed_fixture_is_reported_as_a_failed_package() {
        let packages = vec![OsvPackageQuery {
            ecosystem: "npm".to_string(),
            name: "express".to_string(),
            version: None,
        }];
        let report =
            query_osv_candidates(&packages, 3, 3, Some(&json!({"express": {"bad": true}})));
        assert_eq!(report.failed_packages, vec!["express"]);
        assert!(report.candidates.is_empty());
    }
}
