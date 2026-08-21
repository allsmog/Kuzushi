use super::super::*;

const MAX_QUERIED_PACKAGES: usize = 5;
const MAX_ADVISORIES_PER_PACKAGE: usize = 3;

#[derive(Debug, Clone)]
pub(crate) struct AdvisoryRecord {
    pub(crate) id: String,
    pub(crate) summary: String,
    pub(crate) package: String,
}

/// Offline-first OSV intake for the staged research stage. Precedence
/// mirrors variant_ndiff's fetch policy: inline fixtures beat everything,
/// `offline` blocks the network entirely, and the live path is a bounded
/// https-only curl POST per direct dependency (top manifests only).
pub(crate) fn fetch_osv_advisories(input: &BuildInput) -> Result<Vec<AdvisoryRecord>> {
    if input.advisories != "osv" {
        return Ok(Vec::new());
    }
    if input.offline && input.advisory_fixtures.is_none() {
        return Ok(Vec::new());
    }
    let mut packages = fixture_package_queries(input.advisory_fixtures.as_ref());
    packages.extend(
        direct_dependencies(&input.target)?
            .into_iter()
            .map(
                |(ecosystem, name)| crate::capabilities::threat_intel::OsvPackageQuery {
                    ecosystem,
                    name,
                    version: None,
                },
            ),
    );
    packages.sort();
    packages.dedup();
    packages.truncate(MAX_QUERIED_PACKAGES);
    let report = crate::capabilities::threat_intel::query_osv_candidates(
        &packages,
        MAX_ADVISORIES_PER_PACKAGE,
        MAX_QUERIED_PACKAGES * MAX_ADVISORIES_PER_PACKAGE,
        input.advisory_fixtures.as_ref(),
    );
    Ok(report
        .candidates
        .into_iter()
        .map(|candidate| AdvisoryRecord {
            id: candidate.id,
            summary: candidate.summary,
            package: candidate.package,
        })
        .collect())
}

fn fixture_package_queries(
    fixtures: Option<&Value>,
) -> Vec<crate::capabilities::threat_intel::OsvPackageQuery> {
    fixtures
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|fixtures| fixtures.keys())
        .map(|name| crate::capabilities::threat_intel::OsvPackageQuery {
            ecosystem: "fixture".to_string(),
            name: name.clone(),
            version: None,
        })
        .collect()
}

/// Direct dependencies from the top-level manifests kuzushi already
/// understands. Names are charset-filtered before ever reaching curl argv.
fn direct_dependencies(target: &Path) -> Result<Vec<(String, String)>> {
    let mut dependencies = Vec::new();
    dependencies.extend(package_json_dependencies(target));
    dependencies.extend(cargo_toml_dependencies(target));
    dependencies.extend(requirements_txt_dependencies(target));
    dependencies.retain(|(_, name)| is_safe_package_name(name));
    dependencies.truncate(MAX_QUERIED_PACKAGES);
    Ok(dependencies)
}

fn package_json_dependencies(target: &Path) -> Vec<(String, String)> {
    let Ok(text) = crate::bounded_file::read_utf8_text(&target.join("package.json"), 256 * 1024)
    else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    parsed
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|dependencies| {
            dependencies
                .keys()
                .map(|name| ("npm".to_string(), name.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn cargo_toml_dependencies(target: &Path) -> Vec<(String, String)> {
    let Ok(text) = crate::bounded_file::read_utf8_text(&target.join("Cargo.toml"), 256 * 1024)
    else {
        return Vec::new();
    };
    let Ok(parsed) = toml::from_str::<toml::Value>(&text) else {
        return Vec::new();
    };
    parsed
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .map(|dependencies| {
            dependencies
                .keys()
                .map(|name| ("crates.io".to_string(), name.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn requirements_txt_dependencies(target: &Path) -> Vec<(String, String)> {
    let Ok(text) =
        crate::bounded_file::read_utf8_text(&target.join("requirements.txt"), 256 * 1024)
    else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let name = line
                .split(['=', '<', '>', '~', '!', ';', '#', '['])
                .next()?
                .trim();
            (!name.is_empty()).then(|| ("PyPI".to_string(), name.to_string()))
        })
        .collect()
}

fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '_' | '/' | '.' | '-'))
}

pub(crate) fn advisories_section(records: &[AdvisoryRecord]) -> String {
    if records.is_empty() {
        return String::new();
    }
    let body = records
        .iter()
        .map(|record| format!("- {} · {} · {}", record.id, record.package, record.summary))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Dependency advisories (supply-chain evidence candidates; cite advisory ids as evidence refs):\n{}",
        untrusted_derived_source_block("dependency-advisories", &body)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input(
        temp: &Path,
        advisories: &str,
        offline: bool,
        fixtures: Option<Value>,
    ) -> BuildInput {
        BuildInput {
            target: temp.to_path_buf(),
            repo_name: "t".to_string(),
            methodology: "stride".to_string(),
            sources: vec![],
            seeds: vec![],
            design_doc: None,
            slice: "all".to_string(),
            stages: vec![],
            output_dir: ".kuzushi/tm".to_string(),
            context_mode: "auto".to_string(),
            context_limit: 200,
            max_source_bytes: 200_000,
            max_elements: 40,
            max_threats: 30,
            max_output_tokens: 32_000,
            emit_findings: false,
            preserve_user_edits: true,
            prompt_override: None,
            model: "test:model".to_string(),
            pipeline: "staged".to_string(),
            mode: "build".to_string(),
            seed_mode: "seeded".to_string(),
            budget_usd: None,
            history_depth: 300,
            variant_scan: true,
            advisories: advisories.to_string(),
            offline,
            advisory_fixtures: fixtures,
            vulns: Vec::new(),
        }
    }

    #[test]
    fn advisories_off_fetches_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let input = base_input(temp.path(), "off", false, None);
        assert!(fetch_osv_advisories(&input).unwrap().is_empty());
    }

    #[test]
    fn fixtures_beat_the_network_and_offline_blocks_it() {
        let temp = tempfile::tempdir().unwrap();
        let fixtures = json!({
            "express": [{"id": "GHSA-xxxx-1234", "summary": "prototype pollution"}]
        });
        let input = base_input(temp.path(), "osv", true, Some(fixtures));
        let records = fetch_osv_advisories(&input).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "GHSA-xxxx-1234");
        assert_eq!(records[0].package, "express");

        let offline_no_fixtures = base_input(temp.path(), "osv", true, None);
        assert!(
            fetch_osv_advisories(&offline_no_fixtures)
                .unwrap()
                .is_empty(),
            "offline without fixtures must skip, never fetch"
        );
    }

    #[test]
    fn direct_dependencies_are_bounded_and_charset_filtered() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"4","bad name!":"1","a":"1","b":"1","c":"1","d":"1","e":"1"}}"#,
        )
        .unwrap();
        let dependencies = direct_dependencies(temp.path()).unwrap();
        assert!(dependencies.len() <= MAX_QUERIED_PACKAGES);
        assert!(dependencies
            .iter()
            .all(|(_, name)| is_safe_package_name(name)));
        assert!(!dependencies.iter().any(|(_, name)| name == "bad name!"));
    }
}
