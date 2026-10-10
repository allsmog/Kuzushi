use super::*;
use crate::attack_surface::{AttackSurface, AttackSurfaceKind, AttackSurfaceRisk};
use crate::findings::{Finding, FindingListFilter, FindingStore, ProofConfidence};

#[cfg(test)]
mod rust_test_scope_tests;

/// Deterministic evidence handed to the agentic build so the model reasons
/// over ground truth instead of re-deriving the surface from raw inventory.
pub(crate) struct PromptGrounding {
    pub(crate) surfaces: Vec<AttackSurface>,
    pub(crate) confirmed_findings: Vec<ConfirmedFindingRow>,
    pub(crate) entry_point_catalog: crate::capabilities::entry_points::EntryPointCatalogGrounding,
    pub(crate) selection: GroundingSelection,
}

/// How many ground-truth surfaces the prompt was shown out of how many were
/// discovered, and the bound that decided it. A bounded selection must be
/// disclosed, or "40 surfaces" reads as the whole attack surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GroundingSelection {
    pub(crate) selected: usize,
    pub(crate) available: usize,
    pub(crate) limit: usize,
}

impl GroundingSelection {
    pub(crate) fn dropped(&self) -> usize {
        self.available.saturating_sub(self.selected)
    }

    /// `40 of 70 surfaces (cap 40 · ≤2 rows/file)`; the bound is named only
    /// when it actually left discovered surfaces out of the prompt.
    pub(crate) fn surfaces_label(&self) -> String {
        let counts = format!("{} of {} surfaces", self.selected, self.available);
        if self.dropped() == 0 {
            return counts;
        }
        format!(
            "{counts} (cap {} · ≤{MAX_GROUNDING_ROWS_PER_FILE} rows/file)",
            self.limit
        )
    }

    fn coverage_json(&self) -> Value {
        json!({
            "surfacesAvailable": self.available,
            "surfacesSelected": self.selected,
            "limit": self.limit,
            "maxRowsPerFile": MAX_GROUNDING_ROWS_PER_FILE,
        })
    }
}

/// Record the grounding denominator next to the measured coverage, so the
/// persisted `coverage` block states what the model was never shown.
pub(crate) fn stamp_grounding_selection(document: &mut Value, selection: &GroundingSelection) {
    let Some(root) = document.as_object_mut() else {
        return;
    };
    object_field(root, "coverage").insert("grounding".to_string(), selection.coverage_json());
}

/// Surfaces chosen for the prompt plus the distinct candidate count they
/// were chosen from.
struct SelectedSurfaces {
    surfaces: Vec<AttackSurface>,
    catalog_selected: usize,
    available: usize,
}

pub(crate) struct ConfirmedFindingRow {
    pub(crate) fingerprint: String,
    pub(crate) title: String,
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    pub(crate) severity: &'static str,
    /// CWE named by the finding's title, rule, category, or message.
    pub(crate) cwe: Option<String>,
    /// Code the detector recorded as evidence (sink evidence first), as it
    /// was when the finding was made; later edits such as an applied patch
    /// do not rewrite it.
    pub(crate) evidence_snippet: Option<String>,
}

pub(crate) const MAX_CONFIRMED_FINDING_ROWS: usize = 25;

pub(crate) fn load_prompt_grounding(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PromptGrounding> {
    let scoped = is_non_root_scope(input);
    let catalog = if scoped {
        disabled_catalog_resolution(input)
    } else {
        load_entry_point_catalog(input)?
    };
    let catalog_rows = (!scoped).then_some(catalog.catalog.as_ref()).flatten();
    let selected =
        prompt_grounding_surfaces(input.analysis_root(), input.max_elements, catalog_rows)?;
    let mut surfaces = selected.surfaces;
    rebase_grounding_surfaces(input, &mut surfaces);
    let limit = input.max_elements.max(1);
    let entry_point_catalog =
        catalog_grounding(&catalog, selected.catalog_selected, limit, surfaces.len());
    let selection = GroundingSelection {
        selected: surfaces.len(),
        available: selected.available,
        limit,
    };
    Ok(PromptGrounding {
        surfaces,
        confirmed_findings: confirmed_finding_rows(input, ctx)?,
        entry_point_catalog,
        selection,
    })
}

fn is_non_root_scope(input: &BuildInput) -> bool {
    input
        .roots
        .scope
        .as_ref()
        .is_some_and(|scope| scope.rel_path != Path::new("."))
}

fn rebase_grounding_surfaces(input: &BuildInput, surfaces: &mut [AttackSurface]) {
    let Some(scope) = input.roots.scope.as_ref() else {
        return;
    };
    if scope.rel_path == Path::new(".") {
        return;
    }
    for surface in surfaces {
        surface.path = scope
            .rel_path
            .join(&surface.path)
            .to_string_lossy()
            .replace('\\', "/");
        surface.id = crate::workspace::attack_surface::attack_surface_id(surface);
    }
}

fn load_entry_point_catalog(
    input: &BuildInput,
) -> Result<crate::capabilities::entry_points::EntryPointCatalogResolution> {
    if catalog_loading_disabled(input) {
        return Ok(disabled_catalog_resolution(input));
    }
    if input.context_mode == "off" {
        return crate::capabilities::entry_points::load_explicit_entry_point_catalog(
            input.workspace_root(),
        );
    }
    load_current_or_explicit_catalog(input)
}

fn catalog_loading_disabled(input: &BuildInput) -> bool {
    has_catalog_source(input, "none")
        || (input.context_mode == "off" && !has_catalog_source(input, "entry-points"))
}

fn has_catalog_source(input: &BuildInput, expected: &str) -> bool {
    input.sources.iter().any(|source| source == expected)
}

fn load_current_or_explicit_catalog(
    input: &BuildInput,
) -> Result<crate::capabilities::entry_points::EntryPointCatalogResolution> {
    let resolution = crate::capabilities::entry_points::ensure_current_entry_point_catalog(
        input.workspace_root(),
    )?;
    if resolution.catalog.is_none() && has_catalog_source(input, "entry-points") {
        return crate::capabilities::entry_points::load_explicit_entry_point_catalog(
            input.workspace_root(),
        );
    }
    Ok(resolution)
}

fn disabled_catalog_resolution(
    input: &BuildInput,
) -> crate::capabilities::entry_points::EntryPointCatalogResolution {
    crate::capabilities::entry_points::EntryPointCatalogResolution {
        catalog: None,
        status: if is_non_root_scope(input) {
            "scoped-derived".to_string()
        } else {
            "disabled".to_string()
        },
        path: crate::workspace::workspace_state_root(input.workspace_root())
            .join("entry-points.json"),
    }
}

fn prompt_grounding_surfaces(
    target: &Path,
    max_elements: usize,
    catalog: Option<&crate::capabilities::entry_points::EntryPointCatalog>,
) -> Result<SelectedSurfaces> {
    let Some(catalog) = catalog else {
        let (surfaces, available) = counted_grounding_surfaces(target, max_elements)?;
        return Ok(SelectedSurfaces {
            surfaces,
            catalog_selected: 0,
            available,
        });
    };
    let limit = max_elements.max(1);
    let catalog_limit = catalog_selection_limit(limit, catalog.total);
    catalog_grounding_surfaces(target, limit, catalog, catalog_limit)
}

fn catalog_grounding_surfaces(
    target: &Path,
    limit: usize,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    catalog_limit: usize,
) -> Result<SelectedSurfaces> {
    let catalog_rows: Vec<AttackSurface> = catalog
        .entry_points
        .iter()
        .map(|entry| entry.surface.clone())
        .collect();
    let catalog_available = distinct_surface_count(&catalog_rows);
    let mut selected = stratified_top_surfaces(catalog_rows, catalog_limit);
    let catalog_selected = selected.len();
    let noncatalog_available = fill_non_catalog_surfaces(target, limit, catalog, &mut selected)?;
    Ok(SelectedSurfaces {
        surfaces: selected,
        catalog_selected,
        available: catalog_available + noncatalog_available,
    })
}

fn distinct_surface_count<'a>(surfaces: impl IntoIterator<Item = &'a AttackSurface>) -> usize {
    surfaces
        .into_iter()
        .map(|surface| surface.id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn catalog_selection_limit(limit: usize, catalog_total: usize) -> usize {
    if catalog_total == 0 {
        return 0;
    }
    limit
        .saturating_mul(3)
        .div_ceil(4)
        .max(1)
        .min(catalog_total)
}

fn fill_non_catalog_surfaces(
    target: &Path,
    limit: usize,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    selected: &mut Vec<AttackSurface>,
) -> Result<usize> {
    let catalog_ids = catalog
        .entry_points
        .iter()
        .map(|entry| entry.surface.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut candidates = crate::attack_surface::build_attack_surface_map(target)
        .context("threat-model grounding: attack-surface map failed")?
        .surfaces;
    candidates.extend(infra_surface_rows(target));
    candidates.retain(|surface| !catalog_ids.contains(surface.id.as_str()));
    let available = distinct_surface_count(&candidates);
    append_unique_surfaces(selected, stratified_top_surfaces(candidates, limit), limit);
    Ok(available)
}

fn append_unique_surfaces(
    selected: &mut Vec<AttackSurface>,
    candidates: Vec<AttackSurface>,
    limit: usize,
) {
    let mut ids = selected
        .iter()
        .map(|surface| surface.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for surface in candidates {
        if selected.len() >= limit {
            return;
        }
        if ids.insert(surface.id.clone()) {
            selected.push(surface);
        }
    }
}

fn catalog_grounding(
    resolution: &crate::capabilities::entry_points::EntryPointCatalogResolution,
    records_selected: usize,
    grounding_limit: usize,
    grounding_records_selected: usize,
) -> crate::capabilities::entry_points::EntryPointCatalogGrounding {
    let Some(catalog) = resolution.catalog.as_ref() else {
        let mut grounding =
            crate::capabilities::entry_points::EntryPointCatalogGrounding::unavailable(
                &resolution.status,
            );
        grounding.receipt.grounding_limit = grounding_limit;
        grounding.receipt.grounding_records_selected = grounding_records_selected;
        return grounding;
    };
    crate::capabilities::entry_points::EntryPointCatalogGrounding {
        receipt: catalog_receipt(
            catalog,
            &resolution.status,
            records_selected,
            grounding_limit,
            grounding_records_selected,
        ),
        catalog_ids: catalog
            .entry_points
            .iter()
            .map(|entry| entry.surface.id.clone())
            .collect(),
        catalog_surfaces: catalog
            .entry_points
            .iter()
            .map(|entry| entry.surface.clone())
            .collect(),
    }
}

fn catalog_receipt(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    status: &str,
    records_selected: usize,
    grounding_limit: usize,
    grounding_records_selected: usize,
) -> crate::capabilities::entry_points::EntryPointCatalogReceipt {
    let provenance = &catalog.provenance;
    crate::capabilities::entry_points::EntryPointCatalogReceipt {
        status: status.to_string(),
        sha256: Some(provenance.sha256.clone()),
        records: catalog.total,
        records_selected,
        grounding_limit,
        grounding_records_selected,
        snapshot_timestamp: Some(catalog.snapshot_timestamp),
        context_sha256: Some(provenance.context_snapshot_sha256.clone()),
        tree_hash: provenance.context_snapshot_tree_hash.clone(),
        selection_policy: crate::capabilities::entry_points::ENTRY_POINT_SELECTION_POLICY
            .to_string(),
        revision: provenance.revision.clone(),
        revision_dirty: provenance.revision_dirty,
    }
}

pub(crate) fn stamp_entry_point_catalog_receipt(
    document: &mut Value,
    catalog: &crate::capabilities::entry_points::EntryPointCatalogGrounding,
) {
    let Some(root) = document.as_object_mut() else {
        return;
    };
    let provenance = object_field(root, "provenance");
    provenance.insert("entryPointCatalog".to_string(), catalog.receipt.json());
    let linked = linked_catalog_entry_points(document, &catalog.catalog_ids);
    let Some(root) = document.as_object_mut() else {
        return;
    };
    let coverage = object_field(root, "coverage");
    coverage.insert(
        "catalogEntryPointsTotal".to_string(),
        json!(catalog.receipt.records),
    );
    coverage.insert(
        "catalogEntryPointsSelected".to_string(),
        json!(catalog.receipt.records_selected),
    );
    coverage.insert("catalogEntryPointsLinked".to_string(), json!(linked));
}

fn object_field<'a>(root: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    if !root.get(key).is_some_and(Value::is_object) {
        root.insert(key.to_string(), json!({}));
    }
    root.get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("object field")
}

fn linked_catalog_entry_points(document: &Value, catalog_ids: &BTreeSet<String>) -> usize {
    document
        .pointer("/attackSurface/entryPoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .filter(|id| catalog_ids.contains(*id))
        .collect::<BTreeSet<_>>()
        .len()
}

/// Context-free grounding surfaces (ranked code surfaces + infra rows) —
/// shared by prompt grounding and document verification, so coverage is
/// always measured against the same ground truth the build saw.
pub(crate) fn grounding_surfaces(target: &Path, max_elements: usize) -> Result<Vec<AttackSurface>> {
    Ok(counted_grounding_surfaces(target, max_elements)?.0)
}

/// Context-free grounding surfaces plus the distinct discovered-candidate
/// count they were selected from.
fn counted_grounding_surfaces(
    target: &Path,
    max_elements: usize,
) -> Result<(Vec<AttackSurface>, usize)> {
    let candidates = crate::attack_surface::build_attack_surface_map(target)
        .context("threat-model grounding: attack-surface map failed")?
        .surfaces;
    let infra = infra_surface_rows(target);
    let available = distinct_surface_count(candidates.iter().chain(&infra));
    let mut surfaces = stratified_top_surfaces(candidates, max_elements.max(1));
    surfaces.extend(infra);
    Ok((surfaces, available))
}

const MAX_INFRA_SURFACE_ROWS: usize = 24;
const MAX_ROWS_PER_MANIFEST_DIR: usize = 8;
const MANIFEST_DIRS: &[&str] = &[
    "k8s",
    "deploy",
    "deployment",
    "manifests",
    "helm",
    "infra",
    "terraform",
];
const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "go.sum",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
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
            rows.push(infra_row(
                AttackSurfaceKind::InfraConfig,
                &name,
                format!("Container build: {name}"),
            ));
        } else if name.starts_with("docker-compose") && has_yaml_extension(&name) {
            rows.push(infra_row(
                AttackSurfaceKind::InfraConfig,
                &name,
                format!("Container orchestration: {name}"),
            ));
        } else if name.ends_with(".tf") {
            rows.push(infra_row(
                AttackSurfaceKind::InfraConfig,
                &name,
                format!("Infrastructure as code: {name}"),
            ));
        } else if LOCKFILES.contains(&name.as_str()) {
            rows.push(infra_row(
                AttackSurfaceKind::SupplyChain,
                &name,
                format!("Dependency lockfile: {name}"),
            ));
        } else if (name == "vendor" || name == "third_party") && target.join(&name).is_dir() {
            rows.push(infra_row(
                AttackSurfaceKind::SupplyChain,
                &name,
                format!("Vendored dependencies: {name}/"),
            ));
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
            rows.push(infra_row(
                AttackSurfaceKind::InfraConfig,
                &path,
                format!("Deployment manifest: {path}"),
            ));
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
        rows.push(infra_row(
            AttackSurfaceKind::SupplyChain,
            &path,
            format!("CI workflow: {path}"),
        ));
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
        take_one_round(
            &mut buckets,
            max_elements,
            &mut selected,
            &mut rows_per_file,
        );
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

fn confirmed_finding_rows(
    input: &BuildInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Vec<ConfirmedFindingRow>> {
    let opened;
    let store = match ctx.findings_store {
        Some(store) => store,
        None => match open_existing_findings_store(input)? {
            Some(store) => {
                opened = store;
                &opened
            }
            None => return Ok(Vec::new()),
        },
    };
    // Confirmed = runtime-exploited; Likely = statically-supported
    // (code-cited / source-sink / statically-confirmed). Both are legitimate
    // evidence rows — the band travels with each row so the model can weight
    // them differently.
    let filter = FindingListFilter {
        confidence: vec![ProofConfidence::Confirmed, ProofConfidence::Likely],
        limit: usize::MAX,
        ..Default::default()
    };
    let report = store
        .list_findings_filtered(&filter)
        .context("threat-model grounding: confirmed-findings query failed")?;
    let mut findings = report.findings;
    append_review_confirmed(store, &mut findings)?;
    Ok(findings
        .into_iter()
        .filter(|finding| finding_belongs_to_analysis_root(input, finding))
        .take(MAX_CONFIRMED_FINDING_ROWS)
        .map(confirmed_row)
        .collect())
}

/// Modes hand the optional store only to tools that require one, so a
/// headless or shell build opens the workspace's existing ledger itself, the
/// same way modes open it for tools that require it. A workspace with no
/// findings database has nothing to cite and gets none created.
fn open_existing_findings_store(input: &BuildInput) -> Result<Option<FindingStore>> {
    let workspace = crate::workspace::WorkspaceTarget::new(input.workspace_root())?;
    let path = workspace.findings_db_path();
    if !path.is_file() {
        return Ok(None);
    }
    FindingStore::open(&path)
        .map(Some)
        .context("threat-model grounding: could not open the findings ledger")
}

/// Findings a triage verdict or review decision confirmed, even when no
/// proof has raised their confidence band yet: the same decision in force
/// that authorizes verify, patch, and variant hunting. Proof-banded rows
/// come first and are not repeated.
fn append_review_confirmed(store: &FindingStore, findings: &mut Vec<Finding>) -> Result<()> {
    let relevant = store
        .list_relevant_findings()
        .context("threat-model grounding: relevant-findings query failed")?;
    let decisions = store.list_review_decisions_for_findings(&relevant)?;
    let index = crate::findings::EffectiveReviewStateIndex::from_findings_and_decisions(
        &relevant, &decisions,
    );
    let mut seen: BTreeSet<String> = findings.iter().map(|f| f.fingerprint.clone()).collect();
    for finding in relevant {
        let decision = index.effective_decision_for(&finding);
        let gate = crate::findings::FindingReviewGate::from_effective(&finding, decision.as_ref());
        let confirmed = matches!(gate, crate::findings::FindingReviewGate::Confirmed(_));
        if confirmed && seen.insert(finding.fingerprint.clone()) {
            findings.push(finding);
        }
    }
    Ok(())
}

fn finding_belongs_to_analysis_root(input: &BuildInput, finding: &Finding) -> bool {
    if !is_non_root_scope(input) {
        return true;
    }
    crate::findings::safe_target_path(input.workspace_root(), &finding.file_path)
        .is_some_and(|path| path.starts_with(input.analysis_root()))
}

fn confirmed_row(finding: Finding) -> ConfirmedFindingRow {
    let cwe = super::super::domain::cwe_from_texts(&[
        &finding.title,
        &finding.rule_id,
        finding.category.as_deref().unwrap_or_default(),
        &finding.message,
    ]);
    let evidence_snippet = detection_snippet(&finding.evidence);
    ConfirmedFindingRow {
        cwe,
        evidence_snippet,
        fingerprint: finding.fingerprint,
        title: finding.title,
        file_path: finding.file_path,
        start_line: finding.start_line,
        severity: finding.severity.as_str(),
    }
}

/// Sink evidence first, then any evidence with a snippet.
fn detection_snippet(evidence: &[crate::findings::FindingEvidence]) -> Option<String> {
    let with_snippet = || evidence.iter().filter(|row| !row.snippet.trim().is_empty());
    with_snippet()
        .find(|row| row.kind.to_ascii_lowercase().contains("sink"))
        .or_else(|| with_snippet().next())
        .map(|row| row.snippet.clone())
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
    let context = surface_context_fields(surface);
    format!(
        "- id={id} · {path}{line} · {kind} · {title} · {context}evidence={evidence} · risk={score} ({tier})",
        id = surface.id,
        path = surface.path,
        kind = surface.kind.as_str(),
        title = surface.title,
        evidence = surface.evidence,
        score = surface.risk.score,
        tier = surface.risk.tier,
    )
}

fn surface_context_fields(surface: &AttackSurface) -> String {
    [
        surface
            .method
            .as_deref()
            .map(|value| format!("method={value} · ")),
        surface
            .route
            .as_deref()
            .map(|value| format!("route={value} · ")),
        surface
            .boundary
            .as_deref()
            .map(|value| format!("boundary={value} · ")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub(crate) fn confirmed_findings_section(rows: &[ConfirmedFindingRow]) -> String {
    if rows.is_empty() {
        return "Corroborated prior findings: none".to_string();
    }
    let body = rows.iter().map(finding_line).collect::<Vec<_>>().join("\n");
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
    use crate::findings::Severity;

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

    fn catalog(rows: Vec<AttackSurface>) -> crate::capabilities::entry_points::EntryPointCatalog {
        let entry_points = rows
            .into_iter()
            .map(
                |surface| crate::capabilities::entry_points::EntryPointRecord {
                    name: json!(surface.title),
                    location: json!(surface.path),
                    surface,
                    extra: Map::new(),
                },
            )
            .collect::<Vec<_>>();
        let sha256 = crate::capabilities::entry_points::entry_points_sha256(&entry_points).unwrap();
        crate::capabilities::entry_points::EntryPointCatalog {
            target: "/repo".to_string(),
            timestamp: 10,
            snapshot_timestamp: 9,
            total: entry_points.len(),
            entry_points,
            snapshot_coverage:
                crate::capabilities::entry_points::EntryPointSnapshotCoverage::Complete,
            provenance: crate::capabilities::entry_points::EntryPointCatalogProvenance {
                built_at_ms: 10,
                sha256,
                revision: Some("abc".to_string()),
                revision_dirty: Some(false),
                context_snapshot_timestamp: 9,
                context_snapshot_sha256: "sha256:context".to_string(),
                context_snapshot_tree_hash: None,
            },
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
    fn grounding_label_discloses_the_denominator_and_names_the_cap_only_when_it_dropped_rows() {
        let capped = GroundingSelection {
            selected: 40,
            available: 70,
            limit: 40,
        };
        assert_eq!(capped.dropped(), 30);
        assert_eq!(
            capped.surfaces_label(),
            "40 of 70 surfaces (cap 40 · ≤2 rows/file)"
        );
        let complete = GroundingSelection {
            selected: 12,
            available: 12,
            limit: 40,
        };
        assert_eq!(complete.dropped(), 0);
        assert_eq!(complete.surfaces_label(), "12 of 12 surfaces");
    }

    #[test]
    fn grounding_selection_is_stamped_additively_into_coverage() {
        let mut document = json!({"coverage": {"entryPointsConsidered": 40}});
        let selection = GroundingSelection {
            selected: 40,
            available: 70,
            limit: 40,
        };

        stamp_grounding_selection(&mut document, &selection);

        assert_eq!(document["coverage"]["entryPointsConsidered"], json!(40));
        assert_eq!(
            document["coverage"]["grounding"],
            json!({
                "surfacesAvailable": 70,
                "surfacesSelected": 40,
                "limit": 40,
                "maxRowsPerFile": MAX_GROUNDING_ROWS_PER_FILE,
            })
        );
    }

    #[test]
    fn uncataloged_grounding_counts_every_discovered_surface_before_the_cap() {
        let target = tempfile::tempdir().unwrap();
        for name in ["Dockerfile", "Cargo.lock", "go.sum"] {
            std::fs::write(target.path().join(name), "x").unwrap();
        }

        let selected = prompt_grounding_surfaces(target.path(), 1, None).unwrap();

        assert_eq!(selected.catalog_selected, 0);
        assert_eq!(selected.available, 3);
        assert_eq!(selected.surfaces.len(), 3, "infra rows are never capped");
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
    fn prompt_selection_bounds_catalog_rows_then_fills_non_catalog_infra() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("Dockerfile"), "FROM scratch").unwrap();
        let catalog = catalog(vec![
            surface_row("one", AttackSurfaceKind::HttpRoute, "src/one.rs", 90),
            surface_row("two", AttackSurfaceKind::RpcHandler, "src/two.rs", 80),
            surface_row(
                "three",
                AttackSurfaceKind::BackgroundJob,
                "src/three.rs",
                70,
            ),
            surface_row("four", AttackSurfaceKind::CliEntrypoint, "src/four.rs", 60),
        ]);

        let SelectedSurfaces {
            surfaces: selected,
            catalog_selected,
            available,
        } = prompt_grounding_surfaces(target.path(), 4, Some(&catalog)).unwrap();

        assert_eq!(catalog_selected, 3);
        assert_eq!(available, 5, "four catalog rows plus the Dockerfile row");
        assert_eq!(selected.len(), 4);
        assert!(selected.iter().any(|surface| surface.path == "Dockerfile"));
        assert_eq!(
            selected
                .iter()
                .map(|surface| &surface.id)
                .collect::<BTreeSet<_>>()
                .len(),
            selected.len()
        );
    }

    #[test]
    fn catalog_receipt_is_system_owned_and_counts_only_stable_id_links() {
        let catalog = catalog(vec![
            surface_row("one", AttackSurfaceKind::HttpRoute, "src/one.rs", 90),
            surface_row("two", AttackSurfaceKind::RpcHandler, "src/two.rs", 80),
        ]);
        let resolution = crate::capabilities::entry_points::EntryPointCatalogResolution {
            catalog: Some(catalog),
            status: "current".to_string(),
            path: PathBuf::from("/repo/.kuzushi/entry-points.json"),
        };
        let grounding = catalog_grounding(&resolution, 1, 4, 4);
        let mut document = json!({
            "attackSurface": {"entryPoints": [
                {"id": "one", "name": "linked"},
                {"id": "two", "name": "seeded catalog row"},
                {"id": "model-only", "name": "not catalog"}
            ]},
            "coverage": {"entryPointsConsidered": 4},
        });

        stamp_entry_point_catalog_receipt(&mut document, &grounding);

        assert_eq!(
            document["provenance"]["entryPointCatalog"]["status"],
            json!("current")
        );
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["records"],
            json!(2)
        );
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["recordsSelected"],
            json!(1)
        );
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["groundingRecordsSelected"],
            json!(4)
        );
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["groundingLimit"],
            json!(4)
        );
        assert_eq!(
            document["provenance"]["entryPointCatalog"]["revision"],
            json!("abc")
        );
        assert_eq!(document["coverage"]["catalogEntryPointsTotal"], json!(2));
        assert_eq!(document["coverage"]["catalogEntryPointsSelected"], json!(1));
        assert_eq!(
            document["coverage"]["catalogEntryPointsLinked"],
            json!(2),
            "linked counts every output overlap and may exceed the bounded selected subset"
        );
        assert_eq!(
            document["attackSurface"]["entryPoints"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn context_off_never_loads_or_refreshes_a_catalog() {
        let target = tempfile::tempdir().unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().to_path_buf(),
                scope: None,
            },
            context_mode: "off".to_string(),
            ..BuildInput::default()
        };

        let resolution = load_entry_point_catalog(&input).unwrap();

        assert_eq!(resolution.status, "disabled");
        assert!(resolution.catalog.is_none());
        assert!(!resolution.path.exists());
    }

    #[test]
    fn sources_none_bypasses_catalog_artifacts() {
        let target = tempfile::tempdir().unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().to_path_buf(),
                scope: None,
            },
            context_mode: "auto".to_string(),
            sources: vec!["none".to_string()],
            ..BuildInput::default()
        };
        std::fs::create_dir_all(crate::workspace::workspace_state_root(target.path())).unwrap();
        std::fs::write(
            crate::workspace::workspace_state_root(target.path()).join("entry-points.json"),
            "malformed but intentionally out of scope",
        )
        .unwrap();

        let resolution = load_entry_point_catalog(&input).unwrap();

        assert_eq!(resolution.status, "disabled");
        assert!(resolution.catalog.is_none());
    }

    #[test]
    fn context_off_honors_an_explicit_self_validating_catalog() {
        let target = tempfile::tempdir().unwrap();
        let mut surface = surface_row("one", AttackSurfaceKind::HttpRoute, "src/one.rs", 90);
        surface.metadata =
            json!({"sourcePolicy": crate::workspace::rust_surface_policy::RUST_SURFACE_POLICY});
        surface.id = crate::workspace::attack_surface::attack_surface_id(&surface);
        let mut catalog = catalog(vec![surface]);
        catalog.target = target.path().canonicalize().unwrap().display().to_string();
        catalog.provenance.revision = None;
        catalog.provenance.revision_dirty = None;
        catalog.provenance.context_snapshot_tree_hash =
            Some(crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap());
        let path = crate::workspace::workspace_state_root(target.path()).join("entry-points.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&catalog).unwrap()).unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root: target.path().to_path_buf(),
                scope: None,
            },
            context_mode: "off".to_string(),
            sources: vec!["entry-points".to_string()],
            ..BuildInput::default()
        };

        let resolution = load_entry_point_catalog(&input).unwrap();

        assert_eq!(resolution.status, "explicit");
        assert_eq!(resolution.catalog.unwrap().total, 1);
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
        assert_eq!(
            by_path("k8s/deploy.yaml").kind,
            AttackSurfaceKind::InfraConfig
        );
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
            cwe: None,
            evidence_snippet: None,
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

    #[test]
    fn scoped_finding_filter_keeps_only_workspace_paths_under_analysis_root() {
        let target = tempfile::tempdir().unwrap();
        let analysis_root = target.path().join("services/api");
        std::fs::create_dir_all(&analysis_root).unwrap();
        let input = BuildInput {
            roots: ThreatModelBuildRoots {
                workspace_root: target.path().to_path_buf(),
                analysis_root,
                scope: Some(ScopeRef {
                    scope_id: "scope_api".to_string(),
                    rel_path: PathBuf::from("services/api"),
                    project_model_sha256: format!("sha256:{}", "a".repeat(64)),
                    target_revision: "fixture".to_string(),
                }),
            },
            ..BuildInput::default()
        };
        let finding = |path| {
            Finding::new_tool(
                "semgrep",
                "CWE-79",
                path,
                1,
                None,
                Severity::High,
                "unsafe output",
            )
        };

        assert!(finding_belongs_to_analysis_root(
            &input,
            &finding("services/api/src/handler.rs")
        ));
        assert!(!finding_belongs_to_analysis_root(
            &input,
            &finding("services/web/src/handler.rs")
        ));
        assert!(!finding_belongs_to_analysis_root(
            &input,
            &finding("../outside.rs")
        ));
    }
}
