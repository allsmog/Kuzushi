use super::*;
use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_THREAT_INTEL_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_THREAT_INTEL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn threat_intel_module() -> BuiltinModule {
    builtin_module(
        "threat-intel",
        "Threat Intelligence Catalog",
        ModuleKind::Intel,
        "Per-target detector catalog seeded from discovered dependencies and CVE history. Each entry \
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
        threat_intel_research_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Optional,
        )),
        threat_intel_list_tool(),
        threat_intel_apply_tool(),
        threat_intel_harvest_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Optional,
        )),
    ]
}

fn threat_intel_research_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-intel:research",
        "Discover target-local packages, send a bounded set of package/version queries to the OSV API, persist CVE candidates, and harvest those IDs into a detector catalog. Invoking this external-action tool explicitly authorizes network access to OSV and advisory/patch sources.",
        vec![
            target_option(),
            opt(
                "maxPackages",
                OptionType::Int,
                "Maximum discovered packages sent to OSV.",
            )
            .integer_range(1, 100)
            .default(json!(20)),
            opt(
                "maxCvesPerPackage",
                OptionType::Int,
                "Maximum OSV candidates retained per package.",
            )
            .integer_range(1, 10)
            .default(json!(3))
            .advanced(),
            opt(
                "maxCves",
                OptionType::Int,
                "Maximum unique CVE/advisory IDs passed to harvest.",
            )
            .integer_range(1, 100)
            .default(json!(20)),
            threat_intel_output_path_option(),
            threat_intel_regression_gate_option(),
            threat_intel_accept_rejected_option(),
            model_option(),
        ],
    )
}

fn threat_intel_discover_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-intel:discover",
        "Deterministic dependency inventory (npm/cargo/pip/go/Bazel) written to .kuzushi threat-intel candidates; it does NOT research CVEs — feed the candidates into threat-intel:harvest for that.",
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
            opt(
                "cves",
                OptionType::StringList,
                "Comma-separated CVE IDs to harvest.",
            )
            .required(),
            threat_intel_output_path_option(),
            threat_intel_regression_gate_option(),
            threat_intel_accept_rejected_option(),
            model_option(),
        ],
    )
}

fn threat_intel_output_path_option() -> OptionSpec {
    opt("outputPath", OptionType::Path, "Destination catalog TOML.").state_write()
}

fn threat_intel_regression_gate_option() -> OptionSpec {
    opt(
        "regressionGate",
        OptionType::Bool,
        "Validate extracted patterns against the explicit target before cataloging them.",
    )
    .default(json!(true))
}

fn threat_intel_accept_rejected_option() -> OptionSpec {
    opt(
        "acceptRejected",
        OptionType::Bool,
        "Keep patterns rejected by the regression gate.",
    )
    .default(json!(false))
    .advanced()
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

pub(in crate::modules) fn run_threat_intel_research(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    emit_research_start(ctx, &target);
    let snapshot = load_context_snapshot_for_discover(&target)?;
    let technologies = collect_technologies(&snapshot);
    let packages = collect_packages(&target)?;
    let osv_packages = collect_osv_packages(&packages, input_limit(input, "maxPackages", 20));
    let report = crate::capabilities::threat_intel::query_osv_candidates(
        &osv_packages,
        input_limit(input, "maxCvesPerPackage", 3),
        input_limit(input, "maxCves", 20),
        None,
    );
    let output_path = write_researched_candidates_json(&target, &technologies, &packages, &report)?;
    let harvest = harvest_researched_candidates(input, ctx, runtime, dispatch_tool, &report)?;
    emit_research_done(ctx, packages.len(), &report);
    Ok(research_response(
        &target,
        &output_path,
        &packages,
        &report,
        harvest,
    ))
}

fn input_limit(input: &Value, key: &str, default: usize) -> usize {
    input
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(default)
}

fn collect_osv_packages(
    packages: &[Value],
    max_packages: usize,
) -> Vec<crate::capabilities::threat_intel::OsvPackageQuery> {
    let mut unique = BTreeSet::new();
    for package in packages.iter().filter_map(osv_package_from_discovery) {
        unique.insert(package);
    }
    unique.into_iter().take(max_packages).collect()
}

fn osv_package_from_discovery(
    package: &Value,
) -> Option<crate::capabilities::threat_intel::OsvPackageQuery> {
    let raw_ecosystem = package.get("ecosystem")?.as_str()?;
    let ecosystem = osv_ecosystem(raw_ecosystem)?;
    let name = package.get("name")?.as_str()?.trim();
    if !safe_osv_package_name(name) {
        return None;
    }
    let raw_version = package.get("version").and_then(Value::as_str).unwrap_or("");
    Some(crate::capabilities::threat_intel::OsvPackageQuery {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: exact_osv_version(raw_ecosystem, raw_version),
    })
}

fn osv_ecosystem(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("npm"),
        "cargo" => Some("crates.io"),
        "pypi" => Some("PyPI"),
        "go" => Some("Go"),
        _ => None,
    }
}

fn safe_osv_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '_' | '/' | '.' | '-'))
}

fn exact_osv_version(ecosystem: &str, version: &str) -> Option<String> {
    let version = version.trim();
    if version.is_empty()
        || version
            .chars()
            .any(|c| c.is_ascii_whitespace() || matches!(c, '^' | '~' | '>' | '<' | '*' | '='))
    {
        return None;
    }
    let version = if ecosystem == "go" {
        version.strip_prefix('v').unwrap_or(version)
    } else {
        version
    };
    Some(version.to_string())
}

fn harvest_researched_candidates(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    report: &crate::capabilities::threat_intel::OsvQueryReport,
) -> Result<Option<Value>> {
    if report.candidates.is_empty() {
        return Ok(None);
    }
    let mut harvest_input = json!({
        "cves": report.candidates.iter().map(|candidate| candidate.id.clone()).collect::<Vec<_>>(),
        "regressionGate": input.get("regressionGate").and_then(Value::as_bool).unwrap_or(true),
        "acceptRejected": input.get("acceptRejected").and_then(Value::as_bool).unwrap_or(false),
    });
    copy_research_harvest_option(input, &mut harvest_input, "outputPath");
    copy_research_harvest_option(input, &mut harvest_input, "model");
    crate::capabilities::threat_intel::harvest_threat_intel_catalog(
        &harvest_input,
        ctx,
        runtime,
        dispatch_tool,
    )
    .map(Some)
}

fn copy_research_harvest_option(input: &Value, output: &mut Value, key: &str) {
    if let Some(value) = input.get(key) {
        output[key] = value.clone();
    }
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
    collect_go_modules_at(target, &target.join("go.mod"), &mut entries)?;
    collect_bazel_module_deps(target, &mut entries)?;
    if entries.is_empty() {
        collect_nested_go_modules(target, &mut entries)?;
    }
    if entries.is_empty() {
        collect_enclosing_bazel_workspace_deps(target, &mut entries)?;
    }
    Ok(entries)
}

/// A Bazel monorepo sub-module usually holds only `BUILD` files; the Go
/// module and repository rules live at the workspace root above it. Read
/// that root (never above the enclosing git root), confined to it.
fn collect_enclosing_bazel_workspace_deps(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let Some(root) = enclosing_bazel_workspace_root(target) else {
        return Ok(());
    };
    collect_go_modules_at(&root, &root.join("go.mod"), entries)?;
    for path in bazel_root_manifest_paths(&root) {
        let Some(body) = read_optional_threat_intel_input(&root, &path)? else {
            continue;
        };
        collect_bazel_dep_rules(&body, entries);
        collect_go_repository_rules(&body, entries);
    }
    Ok(())
}

const BAZEL_WORKSPACE_MARKERS: [&str; 3] = ["MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"];
const MAX_BAZEL_ROOT_ASCENT: usize = 16;

/// The nearest strict ancestor of `target` that marks a Bazel workspace,
/// searched no higher than the enclosing git root.
fn enclosing_bazel_workspace_root(target: &Path) -> Option<std::path::PathBuf> {
    for ancestor in target.ancestors().skip(1).take(MAX_BAZEL_ROOT_ASCENT) {
        if is_bazel_workspace_root(ancestor) {
            return Some(ancestor.to_path_buf());
        }
        if ancestor.join(".git").exists() {
            return None;
        }
    }
    None
}

fn is_bazel_workspace_root(directory: &Path) -> bool {
    BAZEL_WORKSPACE_MARKERS
        .iter()
        .any(|marker| directory.join(marker).is_file())
}

/// Root manifests plus top-level `*.bzl` macro files such as `deps.bzl`,
/// where `go_repository` rules are commonly declared.
fn bazel_root_manifest_paths(root: &Path) -> Vec<std::path::PathBuf> {
    let mut paths: BTreeSet<std::path::PathBuf> =
        BAZEL_WORKSPACE_MARKERS.iter().map(|marker| root.join(marker)).collect();
    if let Ok(children) = std::fs::read_dir(root) {
        paths.extend(
            children
                .flatten()
                .map(|child| child.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "bzl")),
        );
    }
    paths.into_iter().collect()
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

fn collect_go_modules_at(target: &Path, path: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let Some(body) = read_optional_threat_intel_input(target, path)? else {
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

/// Bazel monorepos rarely keep a root go.mod: bzlmod `bazel_dep` rows in
/// MODULE.bazel and `go_repository` rules in WORKSPACE carry the dependency
/// inventory instead — without this fallback a Bazel Go target produced an
/// empty candidate set.
fn collect_bazel_module_deps(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    for path in bazel_manifest_paths(target) {
        let Some(body) = read_optional_threat_intel_input(target, &path)? else {
            continue;
        };
        collect_bazel_dep_rules(&body, entries);
        collect_go_repository_rules(&body, entries);
    }
    Ok(())
}

const MAX_BAZEL_WALK_ENTRIES: usize = 10_000;
const MAX_BAZEL_WALK_DEPTH: usize = 12;

fn bazel_manifest_paths(target: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = BTreeSet::from([
        target.join("MODULE.bazel"),
        target.join("WORKSPACE"),
        target.join("WORKSPACE.bazel"),
    ]);
    let mut queue = VecDeque::from([(target.to_path_buf(), 0_usize)]);
    let mut visited = 0_usize;
    while let Some((directory, depth)) = queue.pop_front() {
        if depth > MAX_BAZEL_WALK_DEPTH || visited >= MAX_BAZEL_WALK_ENTRIES {
            continue;
        }
        collect_bazel_paths_in_directory(&directory, depth, &mut visited, &mut queue, &mut paths);
    }
    paths.into_iter().collect()
}

fn collect_bazel_paths_in_directory(
    directory: &Path,
    depth: usize,
    visited: &mut usize,
    queue: &mut VecDeque<(std::path::PathBuf, usize)>,
    paths: &mut BTreeSet<std::path::PathBuf>,
) {
    let Ok(children) = std::fs::read_dir(directory) else {
        return;
    };
    for child in children.flatten() {
        *visited += 1;
        if *visited > MAX_BAZEL_WALK_ENTRIES {
            break;
        }
        let path = child.path();
        if is_bazel_build_file(&path) {
            paths.insert(path.clone());
        }
        queue_nested_bazel_directory(&child, path, depth, queue);
    }
}

fn queue_nested_bazel_directory(
    child: &std::fs::DirEntry,
    path: std::path::PathBuf,
    depth: usize,
    queue: &mut VecDeque<(std::path::PathBuf, usize)>,
) {
    if child.file_type().is_ok_and(|kind| kind.is_dir()) && !skipped_nested_scan_dir(&path) {
        queue.push_back((path, depth + 1));
    }
}

fn is_bazel_build_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "BUILD" | "BUILD.bazel"))
}

fn collect_bazel_dep_rules(body: &str, entries: &mut Vec<Value>) {
    for rule in bazel_rule_bodies(body, "bazel_dep") {
        if let Some(name) = bazel_attr(rule, "name") {
            entries.push(json!({
                "ecosystem": "bazel",
                "name": name,
                "version": bazel_attr(rule, "version").unwrap_or_default(),
                "scope": "bazel_dep",
            }));
        }
    }
}

fn collect_go_repository_rules(body: &str, entries: &mut Vec<Value>) {
    for rule_name in ["go_repository", "go_mod_download"] {
        for rule in bazel_rule_bodies(body, rule_name) {
            let name = bazel_attr(rule, "importpath").or_else(|| bazel_attr(rule, "path"));
            push_go_repository_entry(name, bazel_version(rule), rule_name, entries);
        }
    }
}

fn bazel_rule_bodies<'a>(body: &'a str, rule_name: &str) -> Vec<&'a str> {
    let pattern = format!(r"(?s)\b{}\s*\((.*?)\)", regex::escape(rule_name));
    let Ok(pattern) = regex::Regex::new(&pattern) else {
        return Vec::new();
    };
    pattern
        .captures_iter(body)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()))
        .collect()
}

fn bazel_version(rule: &str) -> String {
    bazel_attr(rule, "version")
        .or_else(|| bazel_attr(rule, "tag"))
        .unwrap_or_default()
}

fn push_go_repository_entry(
    name: Option<String>,
    version: String,
    scope: &str,
    entries: &mut Vec<Value>,
) {
    if let Some(name) = name {
        entries.push(json!({
            "ecosystem": "go",
            "name": name,
            "version": version,
            "scope": scope,
        }));
    }
}

fn bazel_attr(text: &str, key: &str) -> Option<String> {
    let spaced = format!("{key} =");
    let tight = format!("{key}=");
    let rest = text
        .split(spaced.as_str())
        .nth(1)
        .or_else(|| text.split(tight.as_str()).nth(1))?;
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    Some(rest[start..end].to_string())
}

const NESTED_GO_SCAN_LIMIT: usize = 200;

/// Monorepos keep per-service go.mod files below the root; a bounded
/// first-level scan finds them when the root manifests yielded nothing.
fn collect_nested_go_modules(target: &Path, entries: &mut Vec<Value>) -> Result<()> {
    let Ok(children) = std::fs::read_dir(target) else {
        return Ok(());
    };
    for child in children.flatten().take(NESTED_GO_SCAN_LIMIT) {
        let path = child.path();
        if !path.is_dir() || skipped_nested_scan_dir(&path) {
            continue;
        }
        let go_mod = path.join("go.mod");
        if go_mod.is_file() {
            collect_go_modules_at(target, &go_mod, entries)?;
        }
    }
    Ok(())
}

fn skipped_nested_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| {
            name.starts_with('.') || matches!(name, "vendor" | "node_modules" | "target")
        })
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
    write_candidates_payload(
        target,
        json!({
            "target": target.display().to_string(),
            "timestamp": now_ms()?,
            "technologies": technologies,
            "packages": packages,
            "cves": [],
            "note": "Offline candidate set. Populate `cves` from OSV / NVD / vendor advisories \
                      and feed into `threat-intel:harvest`.",
        }),
    )
}

fn write_researched_candidates_json(
    target: &Path,
    technologies: &[String],
    packages: &[Value],
    report: &crate::capabilities::threat_intel::OsvQueryReport,
) -> Result<std::path::PathBuf> {
    let cves = report
        .candidates
        .iter()
        .map(crate::capabilities::threat_intel::OsvCandidate::to_json)
        .collect::<Vec<_>>();
    write_candidates_payload(
        target,
        json!({
            "target": target.display().to_string(),
            "timestamp": now_ms()?,
            "technologies": technologies,
            "packages": packages,
            "cves": cves,
            "osv": {
                "queriedPackages": report.queried_packages,
                "failedPackages": report.failed_packages,
                "candidateCount": report.candidates.len(),
                "network": "https://api.osv.dev/v1/query",
            },
            "note": "Bounded OSV candidates; threat-intel:research passed these IDs directly to harvest.",
        }),
    )
}

fn write_candidates_payload(target: &Path, body: Value) -> Result<std::path::PathBuf> {
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

fn research_response(
    target: &Path,
    candidates_path: &Path,
    packages: &[Value],
    report: &crate::capabilities::threat_intel::OsvQueryReport,
    harvest: Option<Value>,
) -> Value {
    let harvested = harvest
        .as_ref()
        .and_then(|value| value.pointer("/data/summary/harvested"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output = format!(
        "threat-intel:research discovered {} packages, retained {} OSV candidates, harvested {} catalog entries, and recorded {} OSV query failures\n  Candidates: {}",
        packages.len(),
        report.candidates.len(),
        harvested,
        report.failed_packages.len(),
        candidates_path.display(),
    );
    let artifacts = research_artifacts(candidates_path, harvest.as_ref());
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "candidatesPath": candidates_path.display().to_string(),
            "packageCount": packages.len(),
            "queriedPackages": report.queried_packages,
            "failedPackages": report.failed_packages,
            "cveCount": report.candidates.len(),
            "cves": report.candidates.iter().map(|candidate| candidate.id.clone()).collect::<Vec<_>>(),
            "harvest": harvest,
        }),
    );
    result["artifacts"] = json!(artifacts);
    result
}

fn research_artifacts(candidates_path: &Path, harvest: Option<&Value>) -> Vec<Value> {
    let mut artifacts = vec![json!({
        "label": "OSV CVE candidates",
        "path": candidates_path.display().to_string(),
        "kind": "json",
    })];
    if let Some(rows) = harvest
        .and_then(|value| value.get("artifacts"))
        .and_then(Value::as_array)
    {
        artifacts.extend(rows.iter().cloned());
    }
    artifacts
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
    let result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "outputPath": path.display().to_string(),
            "technologies": technologies,
            "packageCount": packages.len(),
        }),
    );
    disclose_empty_package_inventory(result, packages.is_empty())
}

/// Zero packages is not a clean inventory: no supported manifest was found
/// here or at an enclosing Bazel workspace root, so CVE harvest has nothing
/// to work from. Say so instead of reporting `completed`.
fn disclose_empty_package_inventory(mut result: Value, empty: bool) -> Value {
    if empty {
        result["status"] = json!("partial");
        result["warnings"] = json!([
            "no dependency manifest found (package.json, Cargo.toml, requirements, go.mod, MODULE.bazel/WORKSPACE, or *.bzl at an enclosing Bazel root); the CVE inventory is empty"
        ]);
    }
    result
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

fn emit_research_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "research",
                format!(
                    "threat-intel:research start · OSV network · target={}",
                    target.display()
                ),
            )
            .emit();
    }
}

fn emit_research_done(
    ctx: &ToolExecutionContext<'_>,
    package_count: usize,
    report: &crate::capabilities::threat_intel::OsvQueryReport,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "research",
                format!(
                    "threat-intel:research complete · {package_count} packages · {} CVE candidates · {} query failures",
                    report.candidates.len(),
                    report.failed_packages.len(),
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

    const BAZEL_WORKSPACE_FIXTURE: &str = r#"
go_repository(
    name = "com_github_gorilla_mux",
    importpath = "github.com/gorilla/mux",
    version = "v1.8.0",
)
go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    tag = "v0.21.0",
)
"#;
    const BAZEL_MODULE_FIXTURE: &str = r#"bazel_dep(
    name = "rules_go",
    version = "0.46.0",
)
"#;
    const BAZEL_SERVICE_FIXTURE: &str = r#"
go_mod_download(
    path = "google.golang.org/grpc",
    version = "v1.62.1",
)
"#;
    const BAZEL_LIBRARY_FIXTURE: &str =
        r#"go_repository(importpath = "github.com/google/uuid", version = "v1.6.0")"#;

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

    #[test]
    fn bazel_workspace_go_repositories_yield_packages() {
        let target = tempfile::tempdir().unwrap();
        write_bazel_package_fixture(target.path());

        let packages = collect_packages(target.path()).unwrap();

        let names: Vec<&str> = packages
            .iter()
            .filter_map(|entry| entry.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"github.com/gorilla/mux"), "{names:?}");
        assert!(names.contains(&"golang.org/x/crypto"), "{names:?}");
        assert!(names.contains(&"rules_go"), "{names:?}");
        assert!(names.contains(&"google.golang.org/grpc"), "{names:?}");
        assert!(names.contains(&"github.com/google/uuid"), "{names:?}");
        assert!(packages.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("golang.org/x/crypto")
                && entry.get("version").and_then(Value::as_str) == Some("v0.21.0")
        }));
        assert!(packages.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("google.golang.org/grpc")
                && entry.get("scope").and_then(Value::as_str) == Some("go_mod_download")
        }));
    }

    #[test]
    fn a_bazel_sub_module_reads_its_enclosing_workspace_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join("WORKSPACE"), BAZEL_WORKSPACE_FIXTURE).unwrap();
        std::fs::write(
            root.path().join("deps.bzl"),
            "def go_deps():\n    go_repository(\n        name = \"com_github_pkg_errors\",\n        importpath = \"github.com/pkg/errors\",\n        version = \"v0.9.1\",\n    )\n",
        )
        .unwrap();
        let target = root.path().join("services/gateway");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("BUILD.bazel"), "go_library(name = \"gateway\")\n").unwrap();

        let packages = collect_packages(&target).unwrap();

        let names: Vec<&str> = packages
            .iter()
            .filter_map(|entry| entry.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"github.com/gorilla/mux"), "{names:?}");
        assert!(names.contains(&"github.com/pkg/errors"), "{names:?}");
    }

    #[test]
    fn the_bazel_root_search_stops_at_the_git_root() {
        let outer = tempfile::tempdir().unwrap();
        std::fs::write(outer.path().join("WORKSPACE"), BAZEL_WORKSPACE_FIXTURE).unwrap();
        let repo = outer.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        let target = repo.join("svc");
        std::fs::create_dir_all(&target).unwrap();

        assert!(enclosing_bazel_workspace_root(&target).is_none());
        assert!(collect_packages(&target).unwrap().is_empty());
    }

    #[test]
    fn an_empty_inventory_is_reported_partial_with_a_reason() {
        let result = discover_response(Path::new("/t"), Path::new("/t/c.json"), &[], &[]);

        assert_eq!(result["status"], "partial");
        assert!(result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("no dependency manifest"));
        let found = discover_response(Path::new("/t"), Path::new("/t/c.json"), &[], &[json!({})]);
        assert_eq!(found["status"], "completed");
    }

    fn write_bazel_package_fixture(target: &Path) {
        for (relative_path, body) in [
            ("WORKSPACE", BAZEL_WORKSPACE_FIXTURE),
            ("MODULE.bazel", BAZEL_MODULE_FIXTURE),
            ("services/gateway/BUILD.bazel", BAZEL_SERVICE_FIXTURE),
            ("libs/identity/BUILD", BAZEL_LIBRARY_FIXTURE),
        ] {
            let path = target.join(relative_path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn bazel_build_scan_does_not_follow_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("BUILD"),
            r#"go_repository(importpath = "outside.example/dependency", version = "v1.0.0")"#,
        )
        .unwrap();
        symlink(outside.path(), target.path().join("outside-link")).unwrap();

        let packages = collect_packages(target.path()).unwrap();

        assert!(!packages.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("outside.example/dependency")
        }));
    }

    #[test]
    fn nested_go_module_fallback_covers_monorepos_without_root_manifests() {
        let target = tempfile::tempdir().unwrap();
        let service = target.path().join("gateway");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(
            service.join("go.mod"),
            "module example.com/gateway\n\nrequire github.com/pkg/errors v0.9.1\n",
        )
        .unwrap();

        let packages = collect_packages(target.path()).unwrap();

        assert!(packages.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("github.com/pkg/errors")
        }));
    }

    #[test]
    fn discovered_packages_map_to_bounded_osv_queries() {
        let packages = vec![
            json!({"ecosystem": "go", "name": "github.com/pkg/errors", "version": "v0.9.1"}),
            json!({"ecosystem": "npm", "name": "express", "version": "^4.18.0"}),
            json!({"ecosystem": "bazel", "name": "rules_go", "version": "0.46.0"}),
        ];

        let queries = collect_osv_packages(&packages, 10);

        assert_eq!(queries.len(), 2);
        assert!(queries.iter().any(|query| {
            query.ecosystem == "Go"
                && query.name == "github.com/pkg/errors"
                && query.version.as_deref() == Some("0.9.1")
        }));
        assert!(queries.iter().any(|query| {
            query.ecosystem == "npm" && query.name == "express" && query.version.is_none()
        }));
    }

    #[test]
    fn researched_candidate_ids_flow_directly_into_harvest() {
        let target = tempfile::tempdir().unwrap();
        let workspace = crate::workspace::WorkspaceTarget::new(target.path()).unwrap();
        let config = crate::config::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let report = researched_candidate_report();

        let result = harvest_researched_candidates(
            &json!({"regressionGate": false}),
            &ctx,
            None,
            mock_harvest_dispatch,
            &report,
        )
        .unwrap()
        .unwrap();

        assert_harvested_candidate(&result, target.path());
    }

    fn researched_candidate_report() -> crate::capabilities::threat_intel::OsvQueryReport {
        crate::capabilities::threat_intel::OsvQueryReport {
            candidates: vec![crate::capabilities::threat_intel::OsvCandidate {
                id: "GO-2026-0001".to_string(),
                summary: "bounds bypass".to_string(),
                package: "example.com/gateway".to_string(),
                ecosystem: "Go".to_string(),
                version: Some("1.2.3".to_string()),
            }],
            queried_packages: 1,
            failed_packages: Vec::new(),
        }
    }

    fn mock_harvest_dispatch(
        name: &str,
        input: Value,
        _ctx: &ToolExecutionContext<'_>,
        _runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        match name {
            "ndiff:fetch-cve" => {
                assert_eq!(input["id"], json!("GO-2026-0001"));
                Ok(json!({
                    "ok": true,
                    "data": {"record": {
                        "id": "GO-2026-0001",
                        "description": "bounds bypass",
                        "cwes": ["CWE-125"],
                        "severity": "HIGH"
                    }}
                }))
            }
            "ndiff:extract-fix-pattern" => Ok(json!({
                "ok": true,
                "data": {"pattern": {
                    "cwe": ["CWE-125"],
                    "languages": ["go"],
                    "vulnerableShape": "unchecked index",
                    "fixShape": "bounds check",
                    "detectionQuery": "items[index]",
                    "description": "index bounds bypass",
                    "confidence": "HIGH"
                }}
            })),
            other => panic!("unexpected delegated tool {other}"),
        }
    }

    fn assert_harvested_candidate(result: &Value, target: &Path) {
        assert_eq!(result["data"]["summary"]["totalCves"], json!(1));
        assert_eq!(result["data"]["summary"]["harvested"], json!(1));
        assert!(
            crate::capabilities::threat_intel::harvested_threat_intel_catalog_path(target).exists()
        );
    }
}
