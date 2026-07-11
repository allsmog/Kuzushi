use super::*;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_THREAT_INTEL_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_THREAT_INTEL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn threat_intel_module() -> BuiltinModule {
    builtin_module(
        "threat-intel",
        "Threat Intelligence Catalog",
        ModuleKind::Intel,
        "Per-target detector catalog seeded from a project's CVE history. Each entry \
         describes the source/sink/sanitizer pattern of one historical CVE and dispatches \
         to the right native hunt (uaf-hunt, taint-iris-next, systems-hunt, variant).",
        threat_intel_tools(),
        vec![dag(
            "threat-intel:discover",
            "cve-candidates",
            &["context:build"],
        )],
    )
}

fn threat_intel_tools() -> Vec<ToolDescriptor> {
    vec![
        threat_intel_discover_tool(),
        threat_intel_list_tool(),
        threat_intel_apply_tool(),
        threat_intel_harvest_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Optional,
        )),
    ]
}

fn threat_intel_discover_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-intel:discover",
        "Inspect dependencies and context, then write .kuzushi threat-intel candidates.",
        vec![target_option()],
    )
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
}

fn threat_intel_list_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-intel:list",
        "List the entries declared in a threat-intel catalog TOML.",
        vec![threat_intel_catalog_path_option()],
    )
    .with_policy(tool_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        ToolEffect::Read,
        WorkspaceRequirement::Required,
        FindingStoreRequirement::Optional,
    ))
}

fn threat_intel_apply_tool() -> ToolDescriptor {
    let options = vec![
        threat_intel_catalog_path_option(),
        opt(
            "dryRun",
            OptionType::Bool,
            "Only produce the dispatch plan.",
        )
        .default(json!(true)),
    ];
    tool_with_options(
        "threat-intel:apply",
        "Plan or dispatch catalog entries to their native hunt modules.",
        options,
    )
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Optional,
    ))
}

fn threat_intel_catalog_path_option() -> OptionSpec {
    opt(
        "catalogPath",
        OptionType::Path,
        "Catalog TOML under the active target's .kuzushi/catalogs directory.",
    )
    .workspace_read()
}

fn threat_intel_harvest_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-intel:harvest",
        "Build a catalog TOML from CVE IDs and extracted fix patterns.",
        vec![
            opt("cves", OptionType::Json, "CVE IDs to harvest.").required(),
            opt("outputPath", OptionType::Path, "Destination catalog TOML.").state_write(),
            model_option(),
        ],
    )
}

pub(in crate::modules) fn run_threat_intel_discover(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    emit_discover_start(ctx, &target);
    let snapshot = load_context_snapshot_for_discover(&target)?;
    let technologies = collect_technologies(&snapshot);
    let packages = collect_packages(&target)?;
    let output_path = write_candidates_json(&target, &technologies, &packages)?;
    emit_discover_done(ctx, technologies.len(), packages.len());
    Ok(discover_response(
        &target,
        &output_path,
        &technologies,
        &packages,
    ))
}

fn load_context_snapshot_for_discover(target: &Path) -> Result<Option<Value>> {
    let path = target.join(".kuzushi/context-snapshot.json");
    let Some(body) = read_optional_threat_intel_input(target, &path)? else {
        return Ok(None);
    };
    serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))
        .map(Some)
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

fn collect_packages(target: &Path) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    collect_npm_packages(target, &mut entries)?;
    collect_cargo_packages(target, &mut entries)?;
    collect_python_requirements(target, &mut entries)?;
    collect_go_modules(target, &mut entries)?;
    Ok(entries)
}

fn collect_npm_packages(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let path = target.join("package.json");
    let Some(body) = read_optional_threat_intel_input(target, &path)? else {
        return Ok(());
    };
    let json: Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
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
    Ok(())
}

fn collect_cargo_packages(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let path = target.join("Cargo.toml");
    let Some(body) = read_optional_threat_intel_input(target, &path)? else {
        return Ok(());
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
    Ok(())
}

fn collect_python_requirements(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let path = target.join("requirements.txt");
    let Some(body) = read_optional_threat_intel_input(target, &path)? else {
        return Ok(());
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
    Ok(())
}

fn collect_go_modules(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let path = target.join("go.mod");
    let Some(body) = read_optional_threat_intel_input(target, &path)? else {
        return Ok(());
    };
    let mut in_require = false;
    for raw in body.lines() {
        let line = raw.trim();
        let Some(candidate) = go_requirement_candidate(line, &mut in_require) else {
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
    Ok(())
}

fn go_requirement_candidate<'a>(line: &'a str, in_require: &mut bool) -> Option<&'a str> {
    if line.starts_with("require (") {
        *in_require = true;
        return None;
    }
    if *in_require && line == ")" {
        *in_require = false;
        return None;
    }
    if *in_require {
        return Some(line);
    }
    line.strip_prefix("require ")
}

fn read_optional_threat_intel_input(target: &Path, path: &Path) -> Result<Option<String>> {
    crate::workspace::read_optional_workspace_text(target, path, MAX_THREAT_INTEL_INPUT_BYTES)
        .with_context(|| format!("Could not read threat-intel input {}", path.display()))
}

fn write_candidates_json(
    target: &Path,
    technologies: &[String],
    packages: &[Value],
) -> Result<std::path::PathBuf> {
    let body = json!({
        "target": target.display().to_string(),
        "timestamp": now_ms()?,
        "technologies": technologies,
        "packages": packages,
        "cves": [],
        "note": "Offline candidate set. Populate `cves` from OSV / NVD / vendor advisories \
                 and feed into `threat-intel:harvest`.",
    });
    let encoded =
        serde_json::to_vec_pretty(&body).context("serializing threat-intel candidates")?;
    anyhow::ensure!(
        encoded.len() <= MAX_THREAT_INTEL_OUTPUT_BYTES,
        "threat-intel candidates exceed the {MAX_THREAT_INTEL_OUTPUT_BYTES}-byte output limit"
    );
    crate::workspace::write_workspace_state_file(
        target,
        Path::new(".kuzushi/threat-intel/candidates.json"),
        &encoded,
    )
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

fn emit_discover_done(ctx: &ToolExecutionContext<'_>, tech_count: usize, package_count: usize) {
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

#[cfg(test)]
mod discover_input_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn package_discovery_rejects_manifest_symlinks() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "API_KEY=outside-secret\n").unwrap();
        symlink(outside.path(), target.path().join("requirements.txt")).unwrap();

        let error = collect_packages(target.path()).unwrap_err();

        assert!(format!("{error:#}").contains("symlink"));
    }

    #[test]
    fn package_discovery_rejects_malformed_manifests() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("package.json"), "{not-json").unwrap();

        let error = collect_packages(target.path()).unwrap_err();

        assert!(error.to_string().contains("Could not parse"));
    }
}
