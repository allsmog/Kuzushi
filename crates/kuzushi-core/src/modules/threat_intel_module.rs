use super::*;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn threat_intel_module() -> BuiltinModule {
    builtin_module(
        "threat-intel",
        "Threat Intelligence Catalog",
        ModuleKind::Intel,
        "Per-target detector catalog seeded from a project's CVE history. Each entry \
         describes the source/sink/sanitizer pattern of one historical CVE and dispatches \
         to the right native hunt (uaf-hunt, taint-iris-next, systems-hunt, variant).",
        vec![
            tool_with_options(
                "threat-intel:discover",
                "Inspect dependency manifests and the context snapshot to enumerate the \
                 technologies + packages used by the target. Writes \
                 .kuzushi/threat-intel/candidates.json — a candidate list that can then be \
                 fed into `threat-intel:harvest` once CVE IDs are sourced. Deterministic; \
                 no model cost.",
                vec![target_option()],
            ),
            tool_with_options(
                "threat-intel:list",
                "List the entries declared in a threat-intel catalog TOML.",
                vec![
                    opt(
                        "catalogPath",
                        OptionType::Path,
                        "Path to the catalog TOML. Defaults to the first .toml under <target>/.kuzushi/catalogs/.",
                    ),
                ],
            ),
            tool_with_options(
                "threat-intel:apply",
                "Plan or dispatch the catalog: route each entry to its hunt module. \
                 Defaults to dryRun=true.",
                vec![
                    opt(
                        "catalogPath",
                        OptionType::Path,
                        "Path to the catalog TOML. Defaults to the first .toml under <target>/.kuzushi/catalogs/.",
                    ),
                    opt(
                        "dryRun",
                        OptionType::Bool,
                        "When true (default), produce the dispatch plan without invoking the underlying hunts. Set false to actually spend agent budget.",
                    )
                    .default(json!(true)),
                ],
            ),
            tool_with_options(
                "threat-intel:harvest",
                "Build a catalog TOML from a list of CVE IDs. For each CVE, calls \
                 ndiff:fetch-cve + ndiff:extract-fix-pattern, then writes one entry per \
                 CVE to the output catalog. The `cves` field is the only JSON-only input \
                 (array of strings).",
                vec![
                    opt(
                        "cves",
                        OptionType::Json,
                        "Array of CVE IDs to harvest into catalog entries.",
                    )
                    .required(),
                    opt(
                        "outputPath",
                        OptionType::Path,
                        "Destination catalog TOML. Defaults to <target>/.kuzushi/catalogs/harvested.toml. Existing files are appended to.",
                    ),
                    model_option(),
                ],
            ),
        ],
        vec![dag(
            "threat-intel:discover",
            "cve-candidates",
            &["context:build"],
        )],
    )
}

pub(in crate::modules) fn run_threat_intel_discover(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    emit_discover_start(ctx, &target);
    let snapshot = load_context_snapshot_for_discover(&target);
    let technologies = collect_technologies(&snapshot);
    let packages = collect_packages(&target);
    let output_path = write_candidates_json(&target, &technologies, &packages)?;
    emit_discover_done(ctx, technologies.len(), packages.len());
    Ok(discover_response(
        &target,
        &output_path,
        &technologies,
        &packages,
    ))
}

fn load_context_snapshot_for_discover(target: &Path) -> Option<Value> {
    let path = target.join(".kuzushi/context-snapshot.json");
    let body = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&body).ok()
}

fn collect_technologies(snapshot: &Option<Value>) -> Vec<String> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    let mut languages = collect_string_array(snapshot, &["repoContext", "languages"]);
    let frameworks = collect_string_array(snapshot, &["repoContext", "frameworks"]);
    languages.extend(frameworks);
    languages.sort();
    languages.dedup();
    languages
}

fn collect_string_array(snapshot: &Value, keys: &[&str]) -> Vec<String> {
    let mut current = snapshot;
    for key in keys {
        match current.get(*key) {
            Some(next) => current = next,
            None => return Vec::new(),
        }
    }
    current
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn collect_packages(target: &Path) -> Vec<Value> {
    let mut entries = Vec::new();
    collect_npm_packages(target, &mut entries);
    collect_cargo_packages(target, &mut entries);
    collect_python_requirements(target, &mut entries);
    collect_go_modules(target, &mut entries);
    entries
}

fn collect_npm_packages(target: &Path, entries: &mut Vec<Value>) {
    let body = match fs::read_to_string(target.join("package.json")) {
        Ok(body) => body,
        Err(_) => return,
    };
    let json: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => return,
    };
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        let Some(deps) = json.get(key).and_then(Value::as_object) else {
            continue;
        };
        for (name, version) in deps {
            entries.push(json!({
                "ecosystem": "npm",
                "name": name,
                "version": version.as_str().unwrap_or(""),
                "scope": key,
            }));
        }
    }
}

fn collect_cargo_packages(target: &Path, entries: &mut Vec<Value>) {
    let body = match fs::read_to_string(target.join("Cargo.toml")) {
        Ok(body) => body,
        Err(_) => return,
    };
    for line in body.lines() {
        let trimmed = line.trim();
        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.starts_with('[') || name.contains(' ') {
            continue;
        }
        let version = rest.trim().trim_matches('"');
        entries.push(json!({
            "ecosystem": "cargo",
            "name": name,
            "version": version,
            "scope": "dependencies",
        }));
    }
}

fn collect_python_requirements(target: &Path, entries: &mut Vec<Value>) {
    let body = match fs::read_to_string(target.join("requirements.txt")) {
        Ok(body) => body,
        Err(_) => return,
    };
    for raw in body.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (name, version) = match line.split_once("==") {
            Some((name, version)) => (name.trim(), version.trim()),
            None => (line, ""),
        };
        entries.push(json!({
            "ecosystem": "pypi",
            "name": name,
            "version": version,
            "scope": "requirements",
        }));
    }
}

fn collect_go_modules(target: &Path, entries: &mut Vec<Value>) {
    let body = match fs::read_to_string(target.join("go.mod")) {
        Ok(body) => body,
        Err(_) => return,
    };
    let mut in_require = false;
    for raw in body.lines() {
        let line = raw.trim();
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && line == ")" {
            in_require = false;
            continue;
        }
        let candidate = if in_require {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        if candidate.is_empty() {
            continue;
        }
        let mut parts = candidate.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        entries.push(json!({
            "ecosystem": "go",
            "name": name,
            "version": version,
            "scope": "require",
        }));
    }
}

fn write_candidates_json(
    target: &Path,
    technologies: &[String],
    packages: &[Value],
) -> Result<std::path::PathBuf> {
    let dir = target.join(".kuzushi/threat-intel");
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating {} for threat-intel candidates", dir.display()))?;
    let path = dir.join("candidates.json");
    let body = json!({
        "target": target.display().to_string(),
        "timestamp": now_ms()?,
        "technologies": technologies,
        "packages": packages,
        "cves": [],
        "note": "Offline candidate set. Populate `cves` from OSV / NVD / vendor advisories \
                 and feed into `threat-intel:harvest`.",
    });
    fs::write(&path, serde_json::to_string_pretty(&body).unwrap_or_default())
        .with_context(|| format!("writing threat-intel candidates at {}", path.display()))?;
    Ok(path)
}

fn discover_response(
    target: &Path,
    path: &Path,
    technologies: &[String],
    packages: &[Value],
) -> Value {
    let output = format!(
        "threat-intel:discover detected {} technolog{} and {} package{}\n  Output: {}",
        technologies.len(),
        if technologies.len() == 1 { "y" } else { "ies" },
        packages.len(),
        if packages.len() == 1 { "" } else { "s" },
        path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "outputPath": path.display().to_string(),
            "technologies": technologies,
            "packageCount": packages.len(),
        }),
    )
}

fn emit_discover_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "discover",
                format!("threat-intel:discover start · target={}", target.display()),
            )
            .emit();
    }
}

fn emit_discover_done(
    ctx: &ToolExecutionContext<'_>,
    tech_count: usize,
    package_count: usize,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "discover",
                format!(
                    "threat-intel:discover complete · {} technologies, {} packages",
                    tech_count, package_count
                ),
            )
            .emit();
    }
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}
