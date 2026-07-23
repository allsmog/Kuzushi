use super::*;
use crate::attack_surface::{AttackSurface, AttackSurfaceKind, AttackSurfaceRisk};
use crate::findings::{Finding, FindingListFilter, ProofConfidence};

/// Deterministic evidence handed to the agentic build so the model reasons
/// over ground truth instead of re-deriving the surface from raw inventory.
pub(crate) struct PromptGrounding {
    pub(crate) surfaces: Vec<AttackSurface>,
    pub(crate) confirmed_findings: Vec<ConfirmedFindingRow>,
}

pub(crate) struct ConfirmedFindingRow {
    pub(crate) fingerprint: String,
    pub(crate) title: String,
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    pub(crate) severity: &'static str,
}

pub(crate) const MAX_CONFIRMED_FINDING_ROWS: usize = 25;

pub(crate) fn load_prompt_grounding(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PromptGrounding> {
    Ok(PromptGrounding {
        surfaces: grounding_surfaces(&input.target, input.max_elements)?,
        confirmed_findings: confirmed_finding_rows(ctx)?,
    })
}

/// Context-free grounding surfaces (ranked code surfaces + infra rows) —
/// shared by prompt grounding and document verification, so coverage is
/// always measured against the same ground truth the build saw.
pub(crate) fn grounding_surfaces(target: &Path, max_elements: usize) -> Result<Vec<AttackSurface>> {
    let mut surfaces = top_ranked_surfaces(target, max_elements)?;
    surfaces.extend(infra_surface_rows(target));
    Ok(surfaces)
}

const MAX_INFRA_SURFACE_ROWS: usize = 24;
const MAX_ROWS_PER_MANIFEST_DIR: usize = 8;
const MANIFEST_DIRS: &[&str] = &["k8s", "deploy", "deployment", "manifests", "helm", "infra", "terraform"];
const LOCKFILES: &[&str] = &[
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "go.sum",
    "poetry.lock", "Pipfile.lock", "Gemfile.lock", "composer.lock", "packages.lock.json",
];

/// Deterministic infra/IAM and supply-chain grounding rows: container
/// builds, deployment manifests, IaC, CI workflows, lockfiles, and vendored
/// trees become candidate entry points, so the measured coverage invariant
/// forces the model to threat-model them or park them with a reason.
pub(crate) fn infra_surface_rows(target: &Path) -> Vec<AttackSurface> {
    let mut rows = Vec::new();
    scan_root_entries(target, &mut rows);
    scan_manifest_dirs(target, &mut rows);
    scan_ci_workflows(target, &mut rows);
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    rows.truncate(MAX_INFRA_SURFACE_ROWS);
    rows
}

fn scan_root_entries(target: &Path, rows: &mut Vec<AttackSurface>) {
    for name in sorted_dir_names(target) {
        if name.starts_with("Dockerfile") {
            rows.push(infra_row(AttackSurfaceKind::InfraConfig, &name, format!("Container build: {name}")));
        } else if name.starts_with("docker-compose") && has_yaml_extension(&name) {
            rows.push(infra_row(AttackSurfaceKind::InfraConfig, &name, format!("Container orchestration: {name}")));
        } else if name.ends_with(".tf") {
            rows.push(infra_row(AttackSurfaceKind::InfraConfig, &name, format!("Infrastructure as code: {name}")));
        } else if LOCKFILES.contains(&name.as_str()) {
            rows.push(infra_row(AttackSurfaceKind::SupplyChain, &name, format!("Dependency lockfile: {name}")));
        } else if (name == "vendor" || name == "third_party") && target.join(&name).is_dir() {
            rows.push(infra_row(AttackSurfaceKind::SupplyChain, &name, format!("Vendored dependencies: {name}/")));
        }
    }
}

fn scan_manifest_dirs(target: &Path, rows: &mut Vec<AttackSurface>) {
    for dir in MANIFEST_DIRS {
        let names = sorted_dir_names(&target.join(dir));
        for name in names
            .iter()
            .filter(|name| has_yaml_extension(name) || name.ends_with(".tf"))
            .take(MAX_ROWS_PER_MANIFEST_DIR)
        {
            let path = format!("{dir}/{name}");
            rows.push(infra_row(AttackSurfaceKind::InfraConfig, &path, format!("Deployment manifest: {path}")));
        }
    }
}

fn scan_ci_workflows(target: &Path, rows: &mut Vec<AttackSurface>) {
    let names = sorted_dir_names(&target.join(".github/workflows"));
    for name in names
        .iter()
        .filter(|name| has_yaml_extension(name))
        .take(MAX_ROWS_PER_MANIFEST_DIR)
    {
        let path = format!(".github/workflows/{name}");
        rows.push(infra_row(AttackSurfaceKind::SupplyChain, &path, format!("CI workflow: {path}")));
    }
}

fn sorted_dir_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn has_yaml_extension(name: &str) -> bool {
    name.ends_with(".yml") || name.ends_with(".yaml")
}

fn infra_row(kind: AttackSurfaceKind, path: &str, title: String) -> AttackSurface {
    AttackSurface {
        id: format!("infra-{path}"),
        kind,
        path: path.to_string(),
        line: None,
        language: "config".to_string(),
        framework: None,
        title,
        evidence: "deterministic infra/supply-chain scan".to_string(),
        method: None,
        route: None,
        boundary: None,
        risk: AttackSurfaceRisk::default(),
        metadata: serde_json::Value::Null,
    }
}

fn top_ranked_surfaces(target: &Path, max_elements: usize) -> Result<Vec<AttackSurface>> {
    let map = crate::attack_surface::build_attack_surface_map(target)
        .context("threat-model grounding: attack-surface map failed")?;
    Ok(stratified_top_surfaces(map.surfaces, max_elements.max(1)))
}

/// Maximum grounding rows drawn from one file, so a single hot spot cannot
/// occupy the whole evidence budget.
const MAX_GROUNDING_ROWS_PER_FILE: usize = 2;

/// Kind-stratified top-N. A pure score cut returns a monoculture on monorepo
/// targets — dozens of same-kind rows from adjacent tooling files — leaving
/// the model blind to listeners, RPC handlers, and parsers that a human
/// threat modeler would rank first. Round-robin across kinds (each kind's
/// rows in score order) keeps every detected surface class represented.
fn stratified_top_surfaces(
    mut surfaces: Vec<AttackSurface>,
    max_elements: usize,
) -> Vec<AttackSurface> {
    surfaces.sort_by_key(|surface| std::cmp::Reverse(surface.risk.score));
    let mut selected = round_robin_by_kind(kind_buckets(surfaces), max_elements);
    selected.sort_by_key(|surface| std::cmp::Reverse(surface.risk.score));
    selected
}

fn kind_buckets(surfaces: Vec<AttackSurface>) -> Vec<std::collections::VecDeque<AttackSurface>> {
    let mut buckets: Vec<std::collections::VecDeque<AttackSurface>> = Vec::new();
    let mut index_by_kind = std::collections::BTreeMap::new();
    for surface in surfaces {
        let index = *index_by_kind.entry(surface.kind).or_insert_with(|| {
            buckets.push(std::collections::VecDeque::new());
            buckets.len() - 1
        });
        buckets[index].push_back(surface);
    }
    buckets.sort_by_key(|bucket| std::cmp::Reverse(bucket_top_score(bucket)));
    buckets
}

fn bucket_top_score(bucket: &std::collections::VecDeque<AttackSurface>) -> u16 {
    bucket
        .front()
        .map(|surface| surface.risk.score)
        .unwrap_or_default()
}

fn round_robin_by_kind(
    mut buckets: Vec<std::collections::VecDeque<AttackSurface>>,
    max_elements: usize,
) -> Vec<AttackSurface> {
    let mut selected = Vec::new();
    let mut rows_per_file = std::collections::BTreeMap::new();
    loop {
        let before = selected.len();
        take_one_round(&mut buckets, max_elements, &mut selected, &mut rows_per_file);
        if selected.len() >= max_elements || selected.len() == before {
            return selected;
        }
    }
}

fn take_one_round(
    buckets: &mut [std::collections::VecDeque<AttackSurface>],
    max_elements: usize,
    selected: &mut Vec<AttackSurface>,
    rows_per_file: &mut std::collections::BTreeMap<String, usize>,
) {
    for bucket in buckets.iter_mut() {
        if selected.len() >= max_elements {
            return;
        }
        if let Some(surface) = next_within_file_cap(bucket, rows_per_file) {
            selected.push(surface);
        }
    }
}

fn next_within_file_cap(
    bucket: &mut std::collections::VecDeque<AttackSurface>,
    rows_per_file: &mut std::collections::BTreeMap<String, usize>,
) -> Option<AttackSurface> {
    while let Some(surface) = bucket.pop_front() {
        let taken = rows_per_file.entry(surface.path.clone()).or_insert(0);
        if *taken < MAX_GROUNDING_ROWS_PER_FILE {
            *taken += 1;
            return Some(surface);
        }
    }
    None
}

fn confirmed_finding_rows(ctx: &ToolExecutionContext<'_>) -> Result<Vec<ConfirmedFindingRow>> {
    let Some(store) = ctx.findings_store else {
        return Ok(Vec::new());
    };
    // Confirmed = runtime-exploited; Likely = statically-supported
    // (code-cited / source-sink / statically-confirmed). Both are legitimate
    // evidence rows — the band travels with each row so the model can weight
    // them differently.
    let filter = FindingListFilter {
        confidence: vec![ProofConfidence::Confirmed, ProofConfidence::Likely],
        limit: MAX_CONFIRMED_FINDING_ROWS,
        ..Default::default()
    };
    let report = store
        .list_findings_filtered(&filter)
        .context("threat-model grounding: confirmed-findings query failed")?;
    Ok(report.findings.into_iter().map(confirmed_row).collect())
}

fn confirmed_row(finding: Finding) -> ConfirmedFindingRow {
    ConfirmedFindingRow {
        fingerprint: finding.fingerprint,
        title: finding.title,
        file_path: finding.file_path,
        start_line: finding.start_line,
        severity: finding.severity.as_str(),
    }
}

pub(crate) fn attack_surface_section(surfaces: &[AttackSurface]) -> String {
    let body = if surfaces.is_empty() {
        "(no deterministic attack surfaces detected)".to_string()
    } else {
        surfaces
            .iter()
            .map(surface_line)
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "Deterministic attack-surface map (ground truth: every row below must appear in attackSurface.entryPoints or in deprioritized with a reason):\n{}",
        untrusted_derived_source_block("attack-surface-map", &body)
    )
}

/// Same `<untrusted-source>` armor convention as the source bundle: raw
/// content under a labeled boundary, so file paths and fingerprints stay
/// verbatim-citable (the percent-encoding record frames would mangle `_`,
/// breaking evidence refs and the deterministic coverage match).
pub(crate) fn untrusted_derived_source_block(label: &str, content: &str) -> String {
    format!(
        r#"<untrusted-source label="{label}" kind="derived" path="derived" sha256="{sha256}" truncated="false">
{content}
</untrusted-source>"#,
        sha256 = crate::options::prompt_content_sha256(content),
    )
}

fn surface_line(surface: &AttackSurface) -> String {
    let line = surface
        .line
        .map(|line| format!(":{line}"))
        .unwrap_or_default();
    format!(
        "- {path}{line} · {kind} · {title} · risk={score} ({tier})",
        path = surface.path,
        kind = surface.kind.as_str(),
        title = surface.title,
        score = surface.risk.score,
        tier = surface.risk.tier,
    )
}

pub(crate) fn confirmed_findings_section(rows: &[ConfirmedFindingRow]) -> String {
    if rows.is_empty() {
        return "Corroborated prior findings: none".to_string();
    }
    let body = rows
        .iter()
        .map(finding_line)
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Corroborated prior findings (confirmed or statically-supported; cite fingerprints in threat evidence — evidence raises likelihood, it is not the threat):\n{}",
        untrusted_derived_source_block("confirmed-findings", &body)
    )
}

pub(crate) fn operator_vulns_section(rows: &[OperatorVulnRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let body = rows
        .iter()
        .map(operator_vuln_line)
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Operator-supplied known vulnerabilities (map each to the entry point it traversed, cluster into patch-surviving threat classes, cite the ids as evidence refs — evidence raises likelihood, it is not the threat):\n{}",
        untrusted_derived_source_block("operator-vulns", &body)
    )
}

fn operator_vuln_line(row: &OperatorVulnRow) -> String {
    let mut parts = vec![row.id.clone()];
    for field in [&row.component, &row.title, &row.description] {
        if !field.is_empty() {
            parts.push(field.clone());
        }
    }
    format!("- {}", parts.join(" · "))
}

fn finding_line(row: &ConfirmedFindingRow) -> String {
    format!(
        "- {fingerprint} · {severity} · {file}:{line} · {title}",
        fingerprint = row.fingerprint,
        severity = row.severity,
        file = row.file_path,
        line = row.start_line,
        title = row.title,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_surface::{AttackSurfaceKind, AttackSurfaceRisk};

    fn surface_row(id: &str, kind: AttackSurfaceKind, path: &str, score: u16) -> AttackSurface {
        AttackSurface {
            id: id.to_string(),
            kind,
            path: path.to_string(),
            line: Some(1),
            language: "python".to_string(),
            framework: None,
            title: format!("{id} surface"),
            evidence: "evidence".to_string(),
            method: None,
            route: None,
            boundary: None,
            risk: AttackSurfaceRisk {
                score,
                ..AttackSurfaceRisk::default()
            },
            metadata: serde_json::Value::Null,
        }
    }

    #[test]
    fn stratified_selection_keeps_minority_kinds_out_of_a_monoculture() {
        let mut surfaces: Vec<AttackSurface> = (0..30)
            .map(|index| {
                surface_row(
                    &format!("cmd{index}"),
                    AttackSurfaceKind::CommandExecutionBoundary,
                    &format!("tools/script{index}.py"),
                    90,
                )
            })
            .collect();
        surfaces.push(surface_row(
            "rpc1",
            AttackSurfaceKind::RpcHandler,
            "src/rpc/server.cpp",
            60,
        ));
        surfaces.push(surface_row(
            "deser1",
            AttackSurfaceKind::DeserializationPoint,
            "src/proto/decode.cpp",
            78,
        ));

        let selected = stratified_top_surfaces(surfaces, 10);

        let kinds: Vec<_> = selected.iter().map(|surface| surface.kind).collect();
        assert!(kinds.contains(&AttackSurfaceKind::RpcHandler));
        assert!(kinds.contains(&AttackSurfaceKind::DeserializationPoint));
        assert_eq!(selected.len(), 10);
    }

    #[test]
    fn stratified_selection_caps_rows_per_file() {
        let surfaces: Vec<AttackSurface> = (0..8)
            .map(|index| {
                surface_row(
                    &format!("hot{index}"),
                    AttackSurfaceKind::CommandExecutionBoundary,
                    "src/hot_spot.py",
                    90,
                )
            })
            .collect();

        let selected = stratified_top_surfaces(surfaces, 8);

        assert_eq!(selected.len(), MAX_GROUNDING_ROWS_PER_FILE);
    }

    #[test]
    fn attack_surface_section_renders_ground_truth_rows_in_untrusted_block() {
        let surfaces = vec![AttackSurface {
            id: "s1".to_string(),
            kind: AttackSurfaceKind::HttpRoute,
            path: "src/routes.py".to_string(),
            line: Some(88),
            language: "python".to_string(),
            framework: None,
            title: "GET /admin/debug".to_string(),
            evidence: "@app.route".to_string(),
            method: None,
            route: None,
            boundary: None,
            risk: AttackSurfaceRisk::default(),
            metadata: serde_json::Value::Null,
        }];
        let section = attack_surface_section(&surfaces);
        assert!(section.contains("attack-surface-map"));
        assert!(section.contains("src/routes.py:88"));
        assert!(section.contains("GET /admin/debug"));
        assert!(section.contains("deprioritized"), "coverage rule stated");
    }

    #[test]
    fn infra_scan_grounds_container_ci_manifest_and_supply_chain_rows() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join("Dockerfile"), "FROM scratch").unwrap();
        std::fs::write(root.join("Cargo.lock"), "# lock").unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "on: push").unwrap();
        std::fs::create_dir_all(root.join("k8s")).unwrap();
        std::fs::write(root.join("k8s/deploy.yaml"), "kind: Deployment").unwrap();
        std::fs::create_dir_all(root.join("vendor")).unwrap();

        let rows = infra_surface_rows(root);
        let by_path = |path: &str| {
            rows.iter()
                .find(|row| row.path == path)
                .unwrap_or_else(|| panic!("missing infra row for {path}"))
        };
        assert_eq!(by_path("Dockerfile").kind, AttackSurfaceKind::InfraConfig);
        assert_eq!(by_path("Cargo.lock").kind, AttackSurfaceKind::SupplyChain);
        assert_eq!(
            by_path(".github/workflows/ci.yml").kind,
            AttackSurfaceKind::SupplyChain
        );
        assert_eq!(by_path("k8s/deploy.yaml").kind, AttackSurfaceKind::InfraConfig);
        assert_eq!(by_path("vendor").title, "Vendored dependencies: vendor/");
        assert!(rows.len() <= 24);
        assert!(
            infra_surface_rows(tempfile::tempdir().unwrap().path()).is_empty(),
            "bare repo grounds no infra rows"
        );
    }

    #[test]
    fn operator_vulns_section_lists_rows_and_evidence_rule() {
        let rows = vec![OperatorVulnRow {
            id: "CVE-2026-1234".to_string(),
            title: "heap overflow".to_string(),
            component: "decoder".to_string(),
            description: String::new(),
        }];
        let section = operator_vulns_section(&rows);
        assert!(section.contains("CVE-2026-1234 · decoder · heap overflow"));
        assert!(section.contains("operator-vulns"));
        assert!(section.contains("evidence raises likelihood"));
        assert_eq!(operator_vulns_section(&[]), "");
    }

    #[test]
    fn confirmed_findings_section_cites_fingerprints_and_evidence_rule() {
        let rows = vec![ConfirmedFindingRow {
            fingerprint: "fp3_abc123".to_string(),
            title: "OOB write in decoder".to_string(),
            file_path: "src/codec.c".to_string(),
            start_line: 42,
            severity: "high",
        }];
        let section = confirmed_findings_section(&rows);
        assert!(section.contains("fp3_abc123"));
        assert!(section.contains("src/codec.c:42"));
        assert!(section.contains("evidence raises likelihood, it is not the threat"));
        assert_eq!(
            confirmed_findings_section(&[]),
            "Corroborated prior findings: none"
        );
    }
}
