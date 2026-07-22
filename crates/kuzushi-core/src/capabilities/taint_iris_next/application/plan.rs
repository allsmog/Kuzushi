use super::*;

pub(crate) fn build_taint_iris_next_plan(
    target: &Path,
    options: TaintIrisNextInput,
) -> Result<TaintIrisNextPlan> {
    let roots = resolve_taint_iris_next_roots(target, &options)?;
    let source_inventories = collect_taint_iris_next_plan_source_inventories(&roots, &options)?;
    let planning = load_taint_iris_next_planning_context(
        target,
        &roots.repo_root,
        &options,
        &source_inventories.repo,
    )?;
    let catalog_selection = select_taint_iris_next_catalog(
        &roots.repo_root,
        &options,
        &planning,
        &source_inventories.repo,
    )?;
    let catalog = catalog_selection.catalog;
    let structural_queries = build_taint_iris_next_structural_queries(&catalog);
    let prompt_catalog = render_taint_iris_next_catalog(&catalog);
    let backend =
        configure_taint_iris_next_backend(&roots.repo_root, &options, &planning.languages)?;
    Ok(finalize_taint_iris_next_plan(
        target,
        roots,
        source_inventories.scan,
        options,
        planning,
        catalog_selection.discovered_signals,
        catalog,
        structural_queries,
        prompt_catalog,
        backend,
    ))
}

#[allow(clippy::too_many_arguments)]
fn finalize_taint_iris_next_plan(
    target: &Path,
    roots: TaintIrisNextRoots,
    source_paths: std::sync::Arc<[TaintIrisNextSourcePath]>,
    options: TaintIrisNextInput,
    planning: TaintIrisNextPlanningContext,
    discovered_signals: DiscoveredSignals,
    catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    structural_queries: Vec<TaintIrisNextStructuralQuery>,
    prompt_catalog: String,
    backend: TaintIrisNextBackendChoice,
) -> TaintIrisNextPlan {
    TaintIrisNextPlan {
        target: target.to_path_buf(),
        scan_root: roots.scan_root,
        repo_root: roots.repo_root,
        source_paths,
        mode: options.mode,
        caps: options.caps,
        languages: planning.languages,
        context_status: planning.context.status,
        threat_model_status: planning.threat_model.status,
        repo_context: planning.context.value,
        threat_model: planning.threat_model.value,
        catalog,
        structural_queries,
        prompt_catalog,
        backend,
        max_budget_usd: options.max_budget_usd,
        allow_deterministic_fallback: options.allow_deterministic_fallback,
        system_prompt: options.system_prompt,
        cwe_focus: options.cwe_focus,
        discovered_signals,
    }
}

struct TaintIrisNextRoots {
    repo_root: PathBuf,
    scan_root: PathBuf,
}

struct TaintIrisNextSourceInventories {
    repo: std::sync::Arc<[TaintIrisNextSourcePath]>,
    scan: std::sync::Arc<[TaintIrisNextSourcePath]>,
}

fn collect_taint_iris_next_plan_source_inventories(
    roots: &TaintIrisNextRoots,
    options: &TaintIrisNextInput,
) -> Result<TaintIrisNextSourceInventories> {
    let scan: std::sync::Arc<[TaintIrisNextSourcePath]> = std::sync::Arc::from(
        collect_taint_iris_next_source_paths(&roots.scan_root, None)?.into_boxed_slice(),
    );
    let repo = if roots.repo_root == roots.scan_root {
        scan.clone()
    } else {
        let cap = taint_iris_next_repo_inventory_cap(options);
        std::sync::Arc::from(
            collect_taint_iris_next_source_paths(&roots.repo_root, Some(cap))?.into_boxed_slice(),
        )
    };
    Ok(TaintIrisNextSourceInventories { repo, scan })
}

fn taint_iris_next_repo_inventory_cap(options: &TaintIrisNextInput) -> usize {
    if !options.discover_signals {
        return 600;
    }
    options
        .caps
        .max_files_per_query
        .saturating_mul(8)
        .max(2_000)
}

fn resolve_taint_iris_next_roots(
    target: &Path,
    options: &TaintIrisNextInput,
) -> Result<TaintIrisNextRoots> {
    let repo_root = target.to_path_buf();
    let scan_root =
        resolve_taint_iris_next_scan_root(&repo_root, options.target_subdir.as_deref())?;
    Ok(TaintIrisNextRoots {
        repo_root,
        scan_root,
    })
}

fn resolve_taint_iris_next_scan_root(
    repo_root: &Path,
    target_subdir: Option<&str>,
) -> Result<PathBuf> {
    target_subdir.map_or_else(
        || Ok(repo_root.to_path_buf()),
        |subdir| resolve_taint_iris_next_subdir_scan_root(repo_root, subdir),
    )
}

fn resolve_taint_iris_next_subdir_scan_root(repo_root: &Path, subdir: &str) -> Result<PathBuf> {
    let joined = repo_root.join(subdir);
    let canonical_root =
        std::fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let canonical_joined = std::fs::canonicalize(&joined).unwrap_or_else(|_| joined.clone());
    if !canonical_joined.starts_with(&canonical_root) {
        anyhow::bail!("taint-iris-next:hunt targetSubdir escapes --target: {subdir:?}");
    }
    Ok(joined)
}

struct TaintIrisNextPlanningContext {
    context: TaintIrisNextArtifactLoad,
    threat_model: TaintIrisNextArtifactLoad,
    languages: Vec<String>,
    threat_cwes: BTreeSet<String>,
    attack_surface_hints: TaintIrisNextAttackSurfaceHints,
    context_keywords: String,
}

fn load_taint_iris_next_planning_context(
    target: &Path,
    repo_root: &Path,
    options: &TaintIrisNextInput,
    source_paths: &[TaintIrisNextSourcePath],
) -> Result<TaintIrisNextPlanningContext> {
    let context = load_taint_iris_next_context(repo_root);
    let threat_model = load_taint_iris_next_threat_model(repo_root);
    let languages =
        resolve_taint_iris_next_languages(options, context.value.as_ref(), source_paths)?;
    let threat_cwes = collect_taint_iris_next_cwes(threat_model.value.as_ref());
    let attack_surface_hints =
        collect_taint_iris_next_attack_surface_hints(threat_model.value.as_ref());
    let context_keywords = taint_iris_next_context_keywords(context.value.as_ref(), target)?;
    Ok(TaintIrisNextPlanningContext {
        context,
        threat_model,
        languages,
        threat_cwes,
        attack_surface_hints,
        context_keywords,
    })
}

fn resolve_taint_iris_next_languages(
    options: &TaintIrisNextInput,
    context: Option<&Value>,
    source_paths: &[TaintIrisNextSourcePath],
) -> Result<Vec<String>> {
    let mut languages = options.languages.clone();
    languages.extend(taint_iris_next_context_languages(context));
    languages.extend(detect_taint_iris_next_languages_in_paths(source_paths)?);
    Ok(normalized_taint_iris_next_languages(languages))
}

fn normalized_taint_iris_next_languages(languages: Vec<String>) -> Vec<String> {
    languages
        .into_iter()
        .map(|language| normalize_taint_next_language(&language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

struct TaintIrisNextCatalogSelection {
    catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    discovered_signals: DiscoveredSignals,
}

fn select_taint_iris_next_catalog(
    repo_root: &Path,
    options: &TaintIrisNextInput,
    planning: &TaintIrisNextPlanningContext,
    source_paths: &[TaintIrisNextSourcePath],
) -> Result<TaintIrisNextCatalogSelection> {
    let catalog = initial_taint_iris_next_catalog(repo_root, options, planning);
    let discovered_signals =
        discover_taint_iris_next_plan_signals(repo_root, options, &catalog, source_paths)?;
    let catalog = finalize_taint_iris_next_catalog(catalog, options, planning, &discovered_signals);
    Ok(TaintIrisNextCatalogSelection {
        catalog,
        discovered_signals,
    })
}

fn initial_taint_iris_next_catalog(
    repo_root: &Path,
    options: &TaintIrisNextInput,
    planning: &TaintIrisNextPlanningContext,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let ranked = ranked_taint_iris_next_catalog(repo_root, options, planning);
    let catalog = limited_taint_iris_next_catalog(ranked, options.caps.max_catalog_entries);
    filter_taint_iris_next_catalog_by_cwe_focus(catalog, &options.cwe_focus)
}

fn ranked_taint_iris_next_catalog(
    repo_root: &Path,
    options: &TaintIrisNextInput,
    planning: &TaintIrisNextPlanningContext,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let mut ranked = target_or_static_taint_iris_next_catalog(repo_root, planning);
    if !options.extra_catalog_entries.is_empty() {
        ranked = merge_taint_iris_next_extra_entries(ranked, &options.extra_catalog_entries);
    }
    ranked
}

fn target_or_static_taint_iris_next_catalog(
    repo_root: &Path,
    planning: &TaintIrisNextPlanningContext,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    match load_taint_iris_next_target_catalog(repo_root) {
        Some(custom) => sorted_taint_iris_next_catalog(custom),
        None => rank_taint_iris_next_catalog(
            &planning.languages,
            &planning.threat_cwes,
            &planning.context_keywords,
        )
        .into_iter()
        .collect::<Vec<_>>(),
    }
}

fn sorted_taint_iris_next_catalog(
    mut entries: Vec<TaintIrisNextRankedCatalogEntry>,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.score));
    entries
}

fn limited_taint_iris_next_catalog(
    ranked: Vec<TaintIrisNextRankedCatalogEntry>,
    max_entries: usize,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    ranked.into_iter().take(max_entries).collect()
}

fn filter_taint_iris_next_catalog_by_cwe_focus(
    catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    cwe_focus: &[String],
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    if cwe_focus.is_empty() {
        return catalog;
    }
    let allow = normalized_taint_iris_next_cwe_focus(cwe_focus);
    catalog
        .into_iter()
        .filter(|entry| allow.contains(&entry.cwe.to_ascii_uppercase()))
        .collect()
}

fn normalized_taint_iris_next_cwe_focus(cwe_focus: &[String]) -> BTreeSet<String> {
    cwe_focus
        .iter()
        .map(|cwe| cwe.to_ascii_uppercase())
        .collect()
}

fn discover_taint_iris_next_plan_signals(
    repo_root: &Path,
    options: &TaintIrisNextInput,
    catalog: &[TaintIrisNextRankedCatalogEntry],
    source_paths: &[TaintIrisNextSourcePath],
) -> Result<DiscoveredSignals> {
    let catalog_markers = catalog_regex_markers_for_discovery(catalog);
    let discovered_signals = run_taint_iris_next_discovery_for_plan(
        source_paths,
        options,
        &catalog_markers,
    );
    persist_taint_iris_next_discovered_signals(repo_root, &discovered_signals)?;
    Ok(discovered_signals)
}

fn finalize_taint_iris_next_catalog(
    catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    options: &TaintIrisNextInput,
    planning: &TaintIrisNextPlanningContext,
    discovered_signals: &DiscoveredSignals,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let catalog = boost_catalog_with_discovered_signals(catalog, discovered_signals);
    let catalog = boost_catalog_with_attack_surface_hints(catalog, &planning.attack_surface_hints);
    supplement_catalog_with_phantom_focus_entries(
        catalog,
        &planning.attack_surface_hints,
        discovered_signals,
        &options.cwe_focus,
    )
}

fn configure_taint_iris_next_backend(
    repo_root: &Path,
    options: &TaintIrisNextInput,
    languages: &[String],
) -> Result<TaintIrisNextBackendChoice> {
    let mut backend = choose_taint_iris_next_backend(&options.backend, repo_root, languages);
    validate_explicit_taint_iris_next_backend(&backend)?;
    if options.target_subdir.is_none() {
        let c_file_count = count_c_files_under(repo_root);
        if should_recommend_partitioning(repo_root, c_file_count) {
            let parts = postgres_partitions_for(repo_root);
            backend.warnings.push(format!(
                "target looks postgres-shaped with {c_file_count} .c files; consider partitioned \
                 hunts in parallel with `targetSubdir` for each \
                 subdir: {}",
                parts
                    .iter()
                    .take(8)
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(backend)
}

fn validate_explicit_taint_iris_next_backend(backend: &TaintIrisNextBackendChoice) -> Result<()> {
    if !matches!(
        backend.requested.as_str(),
        "codeql" | "joern" | "cpg-rs" | "cpg"
    ) {
        return Ok(());
    }
    if backend.selected == backend.requested
        || (backend.requested == "cpg" && backend.selected == "cpg-rs")
        // backend=joern is retired; its selector redirects to cpg-rs.
        || (backend.requested == "joern" && backend.selected == "cpg-rs")
    {
        return Ok(());
    }
    let reason = backend
        .warnings
        .first()
        .map(|warning| warning.replace(" Using structural evidence.", ""))
        .unwrap_or_else(|| {
            format!(
                "backend={} requested, but the backend is not available",
                backend.requested
            )
        });
    anyhow::bail!("{reason}")
}

/// Cheap .c-file count under a directory. Stops walking after
/// `cap` to keep the partition heuristic from O(tree) scanning a
/// 20GB monorepo just to decide whether to recommend partitioning.
/// Returns the count saturated at `cap`.
fn count_c_files_under(root: &Path) -> usize {
    const CAP: usize = 2000;
    let mut count = 0usize;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if file_count_reached_cap(count, CAP) {
            return count;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if file_count_reached_cap(count, CAP) {
                return count;
            }
            count_c_file_entry(entry, &mut stack, &mut count);
        }
    }
    count
}

fn file_count_reached_cap(count: usize, cap: usize) -> bool {
    count >= cap
}

fn count_c_file_entry(entry: std::fs::DirEntry, stack: &mut Vec<PathBuf>, count: &mut usize) {
    let path = entry.path();
    let Ok(file_type) = entry.file_type() else {
        return;
    };
    if should_descend_taint_plan_dir(&path, file_type.is_dir()) {
        stack.push(path);
    } else if file_type.is_file() && is_c_family_source_path(&path) {
        *count += 1;
    }
}

fn should_descend_taint_plan_dir(path: &Path, is_dir: bool) -> bool {
    is_dir && !is_skipped_taint_plan_dir(path)
}

fn is_skipped_taint_plan_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".kuzushi" | ".git" | "target" | "node_modules")
    )
}

fn is_c_family_source_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("c" | "cpp" | "cc" | "cxx")
    )
}

/// Bridge between `build_taint_iris_next_plan` and the discovery
/// scanner. Reads the same source-file budget the structural pass
/// uses (so we don't slurp the entire postgres tree twice on a hunt;
/// the costs are tracked together). Bails early to an empty signal set
/// when discovery is explicitly disabled or the file walker fails.
///
/// `extra_markers` carries codebase-shape markers lifted from the
/// LLM-built catalog's `regex_markers` field. Empty when no catalog is
/// present, when the LLM emitted no markers, or when the operator is
/// running against the static-fallback catalog.
fn run_taint_iris_next_discovery_for_plan(
    source_paths: &[TaintIrisNextSourcePath],
    options: &TaintIrisNextInput,
    extra_markers: &[OwnedMarkerSpec],
) -> DiscoveredSignals {
    if !options.discover_signals {
        return DiscoveredSignals::default();
    }
    // Hard cap: the discovery sweep is regex-only so it scales linearly
    // with file count, but we don't want to blow $$$ on disk read for a
    // 100k-file repo when the structural pass has its own (smaller)
    // sample. Match the structural pass's `max_files_per_query` cap.
    let max_files = options
        .caps
        .max_files_per_query
        .saturating_mul(8)
        .max(2_000);
    let max_bytes = 256 * 1024;
    let files = match read_taint_iris_next_source_paths(source_paths, Some(max_files), max_bytes) {
        Ok(files) => files,
        Err(_) => return DiscoveredSignals::default(),
    };
    run_taint_iris_next_source_sink_discovery(&files, 16, extra_markers)
}

/// Hard cap on the total number of LLM-curated regex markers fed into a
/// single discovery sweep. Each entry in the catalog can contribute up
/// to its own marker count, but the merged stream stops at this cap.
/// Defensive guard against an LLM that emits hundreds of markers per
/// entry — discovery is O(files × markers × file_size), so an unbounded
/// merge would blow the rg-pass runtime on a postgres-scale codebase.
const CATALOG_MARKER_CAP: usize = 64;

/// Flatten the catalog's `regex_markers` into the `OwnedMarkerSpec`
/// list discovery expects. The catalog's per-entry `cwe` is propagated
/// onto each `OwnedMarkerSpec` (the payload carries no CWE of its own).
/// Iteration order follows the catalog's existing score-descending
/// ordering so the highest-scored CWE's markers land first if we hit
/// the cap.
pub(crate) fn catalog_regex_markers_for_discovery(
    catalog: &[TaintIrisNextRankedCatalogEntry],
) -> Vec<OwnedMarkerSpec> {
    let mut out = Vec::new();
    for entry in catalog {
        for marker in &entry.regex_markers {
            if out.len() >= CATALOG_MARKER_CAP {
                return out;
            }
            // Empty-language markers never fire, so inherit the entry's
            // language list when a marker does not declare its own.
            let languages = if marker.languages.is_empty() {
                entry.languages.clone()
            } else {
                marker.languages.clone()
            };
            out.push(OwnedMarkerSpec {
                pattern: marker.pattern.clone(),
                cwe: entry.cwe.clone(),
                kind: marker.kind.clone(),
                languages,
                marker: if marker.marker.is_empty() {
                    format!("catalog.{}", entry.cwe.to_ascii_lowercase())
                } else {
                    marker.marker.clone()
                },
            });
        }
    }
    out
}

/// Add a small score boost (+15 per overlap, capped at +60) to ranked
/// catalog entries whose source or sink names appear among the
/// discovered primitives. Discovery beats threat-model CWE matching
/// for ranking weight only when the source/sink overlap is strong;
/// the threat-model CWE bonus (+100) still wins when both fire, which
/// is the desired ordering: a CWE that the threat model called out
/// AND we have evidence of in the code is the ideal candidate.
fn boost_catalog_with_discovered_signals(
    mut catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    signals: &DiscoveredSignals,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    if no_discovered_signals(signals) {
        return catalog;
    }
    let indexes = discovery_signal_indexes(signals);
    // pgcrypto-shaped discoveries (mbuf_*, pullf_*, pgp_mpi_*) yield
    // ~16 unique source names per CWE; a cap of 8 alphabetically
    // truncated the parser-layer reads (`pullf_read`, `pgp_mpi_read`)
    // out of the CPG source set and the heap-overflow flow that
    // hinges on them never surfaced. 24 fits the pgcrypto family
    // comfortably while still bounding postgres-scale discoveries
    // (the cpg-rs flow pass enforces its own 200-source per-CWE cap so a
    // pathological codebase can't blow up reachableByFlows runtime).
    const SPLICE_PER_ROLE_PER_ENTRY: usize = 24;
    for entry in &mut catalog {
        apply_discovery_overlap_bonus(entry, &indexes);
        // Splice discovered names of MATCHING CWE into source / sink
        // signal lists so the downstream rg engine actually scans for
        // them (otherwise the +15 bonus only fires on names already
        // in the catalog, and the rg sweep never widens beyond the
        // a-priori catalog set). Restrict to source/sink roles only
        // — never touch sanitizer_signals (Thread B's body-inlining
        // reads from sanitizer_signals and the discovery markers
        // don't carry a "sanitizer" kind today; preserves the cycle-
        // free pipeline order).
        splice_discovered_signals(entry, &indexes, SPLICE_PER_ROLE_PER_ENTRY);
        // Dedup + sort-stable: preserve insertion order via dedup-by-set.
        dedup_signal_list(&mut entry.source_signals);
        dedup_signal_list(&mut entry.sink_signals);
    }
    catalog.sort_by_key(|entry| std::cmp::Reverse(entry.score));
    catalog
}

struct DiscoverySignalIndexes<'a> {
    sources_by_cwe: std::collections::BTreeMap<String, Vec<&'a DiscoveredSignal>>,
    sinks_by_cwe: std::collections::BTreeMap<String, Vec<&'a DiscoveredSignal>>,
    source_names: std::collections::BTreeSet<String>,
    sink_names: std::collections::BTreeSet<String>,
}

fn no_discovered_signals(signals: &DiscoveredSignals) -> bool {
    signals.sources.is_empty() && signals.sinks.is_empty() && signals.entry_points.is_empty()
}

fn discovery_signal_indexes(signals: &DiscoveredSignals) -> DiscoverySignalIndexes<'_> {
    let mut indexes = DiscoverySignalIndexes {
        sources_by_cwe: std::collections::BTreeMap::new(),
        sinks_by_cwe: std::collections::BTreeMap::new(),
        source_names: std::collections::BTreeSet::new(),
        sink_names: std::collections::BTreeSet::new(),
    };
    for signal in signals.sources.iter().chain(signals.entry_points.iter()) {
        indexes
            .sources_by_cwe
            .entry(signal.cwe.to_ascii_uppercase())
            .or_default()
            .push(signal);
        indexes.source_names.insert(signal.name.clone());
    }
    for signal in &signals.sinks {
        indexes
            .sinks_by_cwe
            .entry(signal.cwe.to_ascii_uppercase())
            .or_default()
            .push(signal);
        indexes.sink_names.insert(signal.name.clone());
    }
    indexes
}

fn apply_discovery_overlap_bonus(
    entry: &mut TaintIrisNextRankedCatalogEntry,
    indexes: &DiscoverySignalIndexes<'_>,
) {
    let source_bonus = overlap_bonus(&entry.source_signals, &indexes.source_names, 15);
    let sink_bonus = overlap_bonus(&entry.sink_signals, &indexes.sink_names, 15);
    entry.score = entry
        .score
        .saturating_add((source_bonus + sink_bonus).min(60));
}

fn overlap_bonus(
    signals: &[String],
    discovered_names: &std::collections::BTreeSet<String>,
    points: i32,
) -> i32 {
    signals
        .iter()
        .filter(|signal| discovered_names.contains(*signal))
        .fold(0, |total, _| total.saturating_add(points))
}

fn splice_discovered_signals(
    entry: &mut TaintIrisNextRankedCatalogEntry,
    indexes: &DiscoverySignalIndexes<'_>,
    cap: usize,
) {
    let cwe = entry.cwe.to_ascii_uppercase();
    if let Some(signals) = indexes.sources_by_cwe.get(&cwe) {
        splice_discovered_role(&mut entry.source_signals, &entry.languages, signals, cap);
    }
    if let Some(signals) = indexes.sinks_by_cwe.get(&cwe) {
        splice_discovered_role(&mut entry.sink_signals, &entry.languages, signals, cap);
    }
}

fn splice_discovered_role(
    catalog_signals: &mut Vec<String>,
    languages: &[String],
    discovered: &[&DiscoveredSignal],
    cap: usize,
) {
    let mut already: std::collections::BTreeSet<String> = catalog_signals.iter().cloned().collect();
    let mut spliced = 0usize;
    for signal in discovered {
        if spliced >= cap {
            break;
        }
        if !discovery_language_matches(languages, signal) {
            continue;
        }
        if !already.insert(signal.name.clone()) {
            continue;
        }
        catalog_signals.push(signal.name.clone());
        spliced += 1;
    }
}

fn discovery_language_matches(languages: &[String], signal: &DiscoveredSignal) -> bool {
    languages.is_empty()
        || languages.iter().any(|lang| lang == "any")
        || languages.iter().any(|lang| lang == &signal.language)
}

fn dedup_signal_list(list: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    list.retain(|item| seen.insert(item.clone()));
}

/// Add a +20-per-overlap (capped at +80) boost to ranked catalog
/// entries whose source signals match the threat-model's
/// `attackSurface.entryPoints` or sink signals match its
/// `externalSinks` / `roleGates.guarded`. The bonus stacks on top of
/// the discovery boost from `boost_catalog_with_discovered_signals`,
/// and is intentionally smaller than the existing threat-model CWE
/// bonus (+100) so a CWE that the threat model called out outright
/// still ranks first.
fn boost_catalog_with_attack_surface_hints(
    mut catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    hints: &TaintIrisNextAttackSurfaceHints,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    if hints.is_empty() {
        return catalog;
    }
    let indexes = attack_surface_indexes(hints);
    for entry in &mut catalog {
        entry.score = entry
            .score
            .saturating_add(attack_surface_bonus(entry, &indexes));
    }
    catalog.sort_by_key(|entry| std::cmp::Reverse(entry.score));
    catalog
}

struct AttackSurfaceIndexes {
    sources: std::collections::BTreeSet<String>,
    sinks: std::collections::BTreeSet<String>,
}

fn attack_surface_indexes(hints: &TaintIrisNextAttackSurfaceHints) -> AttackSurfaceIndexes {
    AttackSurfaceIndexes {
        sources: hints.entry_points.iter().cloned().collect(),
        sinks: hints
            .external_sinks
            .iter()
            .chain(hints.role_gates.iter())
            .cloned()
            .collect(),
    }
}

fn attack_surface_bonus(
    entry: &TaintIrisNextRankedCatalogEntry,
    indexes: &AttackSurfaceIndexes,
) -> i32 {
    let source_bonus = overlap_bonus(&entry.source_signals, &indexes.sources, 20);
    let sink_bonus = overlap_bonus(&entry.sink_signals, &indexes.sinks, 20);
    (source_bonus + sink_bonus).min(80)
}

/// Synthesise a phantom `TaintIrisNextRankedCatalogEntry` per CWE in
/// `cwe_focus` that the post-rank/post-boost catalog has no entry
/// for. Source/sink signals come from two complementary sources:
///
/// 1. **Threat-model `attackSurface`** (preferred when populated) —
///    `entryPoints[].name` → source signals, `externalSinks[].name`
///    + `roleGates[].guarded` → sink signals. Lets a human-curated
///    threat model surface per-target patterns (`my_handler`,
///    `do_dangerous_thing`) into the rg projection pipeline.
///
/// 2. **Discovery sweep** (fallback when no threat model exists) —
///    framework-canonical discovery markers
///    (`source_sink_discovery::MARKERS`) for the target's languages.
///    Discovered `entry_points` are projected as sources for the
///    focus CWE, and discovered `sinks` are projected when their
///    intrinsic CWE matches the focus. Without this fallback, the
///    agent's `selectedCwes` validator rejects honest claims like
///    "CWE-94 candidates exist from discovery" on codebases (e.g.
///    postgres) that ship no static CWE-94 catalog entry for C and
///    no threat-model.
///
/// The downstream `build_taint_iris_next_structural_queries` + rg
/// engine pick the phantom signals up and produce role-tagged
/// candidates without further plumbing — the catalog signals are
/// exactly the shape rg wants.
///
/// No-op when:
/// - `cwe_focus` is empty (no operator-supplied focus to backfill)
/// - every focus CWE already has at least one catalog entry
/// - both threat-model hints AND discovery are empty (nothing to
///   draw from)
fn supplement_catalog_with_phantom_focus_entries(
    mut catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    hints: &TaintIrisNextAttackSurfaceHints,
    discovered: &DiscoveredSignals,
    cwe_focus: &[String],
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    if cwe_focus.is_empty() {
        return catalog;
    }
    let represented = represented_catalog_cwes(&catalog);
    let signals = phantom_focus_signal_sources(hints, discovered);
    for cwe in cwe_focus {
        if let Some(entry) = phantom_focus_entry(cwe, &represented, &signals) {
            catalog.push(entry);
        }
    }
    catalog.sort_by_key(|entry| std::cmp::Reverse(entry.score));
    catalog
}

struct PhantomFocusSignalSources {
    threat_sources: Vec<String>,
    threat_sinks: Vec<String>,
    discovery_sources: Vec<String>,
    discovery_sinks_by_cwe: BTreeMap<String, Vec<String>>,
}

fn represented_catalog_cwes(catalog: &[TaintIrisNextRankedCatalogEntry]) -> BTreeSet<String> {
    catalog
        .iter()
        .map(|entry| entry.cwe.to_ascii_uppercase())
        .collect()
}

fn phantom_focus_signal_sources(
    hints: &TaintIrisNextAttackSurfaceHints,
    discovered: &DiscoveredSignals,
) -> PhantomFocusSignalSources {
    PhantomFocusSignalSources {
        threat_sources: sorted_unique(hints.entry_points.clone()),
        threat_sinks: sorted_unique(threat_sink_signals(hints)),
        discovery_sources: ranked_discovery_entry_points(discovered),
        discovery_sinks_by_cwe: discovery_sinks_by_cwe(discovered),
    }
}

fn threat_sink_signals(hints: &TaintIrisNextAttackSurfaceHints) -> Vec<String> {
    hints
        .external_sinks
        .iter()
        .chain(hints.role_gates.iter())
        .cloned()
        .collect()
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn ranked_discovery_entry_points(discovered: &DiscoveredSignals) -> Vec<String> {
    const PHANTOM_DISCOVERY_SOURCE_CAP: usize = 50;
    let mut ranked = discovered
        .entry_points
        .iter()
        .map(|signal| {
            (
                signal.name.clone(),
                entry_point_relevance_score(&signal.name),
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.dedup_by(|a, b| a.0 == b.0);
    ranked.truncate(PHANTOM_DISCOVERY_SOURCE_CAP);
    ranked.into_iter().map(|(name, _)| name).collect()
}

fn discovery_sinks_by_cwe(discovered: &DiscoveredSignals) -> BTreeMap<String, Vec<String>> {
    let mut by_cwe = BTreeMap::new();
    for signal in &discovered.sinks {
        by_cwe
            .entry(signal.cwe.to_ascii_uppercase())
            .or_insert_with(Vec::new)
            .push(signal.name.clone());
    }
    by_cwe
        .values_mut()
        .for_each(|signals| *signals = sorted_unique(std::mem::take(signals)));
    by_cwe
}

fn phantom_focus_entry(
    cwe: &str,
    represented: &BTreeSet<String>,
    signals: &PhantomFocusSignalSources,
) -> Option<TaintIrisNextRankedCatalogEntry> {
    let normalised = cwe.to_ascii_uppercase();
    if represented.contains(&normalised) {
        return None;
    }
    let scoped = phantom_signals_for_cwe(&normalised, signals);
    (!scoped.source_signals.is_empty() || !scoped.sink_signals.is_empty())
        .then(|| phantom_catalog_entry(normalised, scoped))
}

struct ScopedPhantomSignals {
    source_signals: Vec<String>,
    sink_signals: Vec<String>,
    provenance: &'static str,
}

fn phantom_signals_for_cwe(cwe: &str, signals: &PhantomFocusSignalSources) -> ScopedPhantomSignals {
    if has_threat_model_signals(signals) {
        return ScopedPhantomSignals {
            source_signals: signals.threat_sources.clone(),
            sink_signals: signals.threat_sinks.clone(),
            provenance: "Threat-Model Attack Surface",
        };
    }
    ScopedPhantomSignals {
        source_signals: signals.discovery_sources.clone(),
        sink_signals: signals
            .discovery_sinks_by_cwe
            .get(cwe)
            .cloned()
            .unwrap_or_default(),
        provenance: "Discovery Sweep",
    }
}

fn has_threat_model_signals(signals: &PhantomFocusSignalSources) -> bool {
    !signals.threat_sources.is_empty() || !signals.threat_sinks.is_empty()
}

fn phantom_catalog_entry(
    cwe: String,
    signals: ScopedPhantomSignals,
) -> TaintIrisNextRankedCatalogEntry {
    TaintIrisNextRankedCatalogEntry {
        cwe: cwe.clone(),
        name: format!("{} ({cwe})", signals.provenance),
        taint_class: phantom_taint_class_for_cwe(&cwe).to_string(),
        languages: Vec::new(),
        source_signals: signals.source_signals,
        sink_signals: signals.sink_signals,
        sanitizer_signals: Vec::new(),
        structural_queries: Vec::new(),
        regex_markers: Vec::new(),
        score: 50,
        reasons: vec![format!(
            "Synthesised from {}; no static catalog entry covered this focus CWE.",
            signals.provenance
        )],
    }
}

/// Map CWE → catalog-aligned `taintClass` for the phantom-entry path.
/// Aligns with `taint_class_for_discovered_cwe` in
/// `extract_taint_iris_next_evidence/mod.rs`. Kept inline rather than
/// imported because the discovery and threat-model paths call it
/// independently and the mapping is small enough that one shared
/// definition isn't load-bearing.
fn phantom_taint_class_for_cwe(cwe: &str) -> &'static str {
    const PHANTOM_TAINT_CLASSES: &[(&[&str], &str)] = &[
        (&["CWE-78", "CWE-77"], "command-injection"),
        (&["CWE-94"], "code-injection"),
        (&["CWE-426"], "search-path"),
        (&["CWE-269", "CWE-250"], "privesc"),
        (&["CWE-732"], "permission"),
        (&["CWE-862"], "missing-authorization"),
        (&["CWE-89"], "sql-injection"),
        (&["CWE-79"], "xss"),
        (&["CWE-22"], "path-traversal"),
        (&["CWE-918"], "ssrf"),
        (&["CWE-502"], "deserialization"),
    ];
    PHANTOM_TAINT_CLASSES
        .iter()
        .find_map(|(cwes, taint_class)| cwes.contains(&cwe).then_some(*taint_class))
        .unwrap_or("threat-model")
}

#[cfg(test)]
mod count_c_files_under_tests {
    use super::*;

    #[test]
    fn counts_c_family_sources_and_skips_artifact_dirs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("root.c"), "int main(void) { return 0; }").unwrap();
        std::fs::write(temp.path().join("root.rs"), "fn main() {}").unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src").join("a.cpp"), "int f();").unwrap();
        std::fs::write(temp.path().join("src").join("b.cxx"), "int g();").unwrap();
        std::fs::create_dir(temp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            temp.path().join(".kuzushi").join("ignored.c"),
            "int ignored;",
        )
        .unwrap();
        std::fs::create_dir(temp.path().join("node_modules")).unwrap();
        std::fs::write(
            temp.path().join("node_modules").join("ignored.cc"),
            "int ignored;",
        )
        .unwrap();

        assert_eq!(count_c_files_under(temp.path()), 3);
    }
}

#[cfg(test)]
mod phantom_focus_entry_tests {
    use super::*;

    fn entry(cwe: &str, score: i32) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: cwe.to_string(),
            taint_class: "test".to_string(),
            languages: Vec::new(),
            source_signals: Vec::new(),
            sink_signals: Vec::new(),
            sanitizer_signals: Vec::new(),
            structural_queries: Vec::new(),
            regex_markers: Vec::new(),
            score,
            reasons: Vec::new(),
        }
    }

    fn no_signals() -> DiscoveredSignals {
        DiscoveredSignals::default()
    }

    fn discovery_signal(name: &str, cwe: &str) -> DiscoveredSignal {
        DiscoveredSignal {
            name: name.to_string(),
            cwe: cwe.to_string(),
            kind: "test".to_string(),
            language: "c".to_string(),
            marker: "test".to_string(),
            file: "f.c".to_string(),
            line: 1,
        }
    }

    #[test]
    fn synthesises_phantom_for_unrepresented_focus_cwe_from_threat_model() {
        let catalog = vec![entry("CWE-78", 100)];
        let hints = TaintIrisNextAttackSurfaceHints {
            entry_points: vec!["my_handler".to_string()],
            external_sinks: vec!["dlopen".to_string()],
            role_gates: Vec::new(),
        };
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let out = supplement_catalog_with_phantom_focus_entries(
            catalog,
            &hints,
            &no_signals(),
            &cwe_focus,
        );
        // CWE-78 was already represented; CWE-94 needed a phantom.
        let cwes: Vec<&str> = out.iter().map(|e| e.cwe.as_str()).collect();
        assert!(cwes.contains(&"CWE-94"));
        let phantom = out.iter().find(|e| e.cwe == "CWE-94").unwrap();
        assert!(phantom.source_signals.contains(&"my_handler".to_string()));
        assert!(phantom.sink_signals.contains(&"dlopen".to_string()));
        assert_eq!(phantom.taint_class, "code-injection");
        assert!(phantom.name.contains("Threat-Model"));
    }

    #[test]
    fn falls_back_to_discovery_when_no_threat_model() {
        // Postgres-shaped scenario: no threat-model.json at all,
        // but discovery surfaced entry-points + dlopen sinks.
        // Without the discovery fallback, the agent's `selectedCwes`
        // validator rejected an honest CWE-94 selection because the
        // static catalog has no CWE-94 entry for C codebases.
        let catalog = vec![entry("CWE-78", 100)];
        let empty_hints = TaintIrisNextAttackSurfaceHints::default();
        let discovery = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: vec![
                discovery_signal("dlopen", "CWE-94"),
                discovery_signal("load_external_function", "CWE-94"),
            ],
            entry_points: vec![discovery_signal("pg_read_server_files", "CWE-862")],
            discoverers: vec!["test".to_string()],
        };
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let out = supplement_catalog_with_phantom_focus_entries(
            catalog,
            &empty_hints,
            &discovery,
            &cwe_focus,
        );
        let phantom = out.iter().find(|e| e.cwe == "CWE-94").unwrap();
        assert!(phantom.name.contains("Discovery"));
        assert!(phantom
            .source_signals
            .contains(&"pg_read_server_files".to_string()));
        assert!(phantom.sink_signals.contains(&"dlopen".to_string()));
        assert!(phantom
            .sink_signals
            .contains(&"load_external_function".to_string()));
    }

    #[test]
    fn threat_model_takes_precedence_over_discovery() {
        // When both feeds populated, prefer the threat-model: a human
        // (or a high-quality LLM-built model) typically has tighter
        // semantics than the static discovery markers.
        let catalog = vec![entry("CWE-78", 100)];
        let hints = TaintIrisNextAttackSurfaceHints {
            entry_points: vec!["threat_model_handler".to_string()],
            external_sinks: vec!["threat_model_sink".to_string()],
            role_gates: Vec::new(),
        };
        let discovery = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: vec![discovery_signal("dlopen", "CWE-94")],
            entry_points: vec![discovery_signal("pg_fn", "CWE-862")],
            discoverers: vec!["test".to_string()],
        };
        let cwe_focus = vec!["CWE-94".to_string()];
        let out =
            supplement_catalog_with_phantom_focus_entries(catalog, &hints, &discovery, &cwe_focus);
        let phantom = out.iter().find(|e| e.cwe == "CWE-94").unwrap();
        assert!(phantom.name.contains("Threat-Model"));
        assert!(phantom
            .source_signals
            .contains(&"threat_model_handler".to_string()));
        assert!(!phantom.source_signals.contains(&"pg_fn".to_string()));
    }

    #[test]
    fn skips_focus_cwes_already_in_catalog() {
        let catalog = vec![entry("CWE-78", 100), entry("CWE-94", 50)];
        let hints = TaintIrisNextAttackSurfaceHints {
            entry_points: vec!["my_handler".to_string()],
            external_sinks: Vec::new(),
            role_gates: Vec::new(),
        };
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let out = supplement_catalog_with_phantom_focus_entries(
            catalog.clone(),
            &hints,
            &no_signals(),
            &cwe_focus,
        );
        // No new entries — both focus CWEs already represented.
        assert_eq!(out.len(), catalog.len());
    }

    #[test]
    fn no_op_when_focus_empty_or_all_feeds_empty() {
        let catalog = vec![entry("CWE-78", 100)];
        let hints = TaintIrisNextAttackSurfaceHints {
            entry_points: vec!["x".to_string()],
            external_sinks: Vec::new(),
            role_gates: Vec::new(),
        };
        let with_empty_focus = supplement_catalog_with_phantom_focus_entries(
            catalog.clone(),
            &hints,
            &no_signals(),
            &[],
        );
        assert_eq!(with_empty_focus.len(), 1);

        // No threat-model AND no discovery: no phantom even when
        // focus has unrepresented CWEs.
        let empty_hints = TaintIrisNextAttackSurfaceHints::default();
        let with_no_feeds = supplement_catalog_with_phantom_focus_entries(
            catalog.clone(),
            &empty_hints,
            &no_signals(),
            &["CWE-94".to_string()],
        );
        assert_eq!(with_no_feeds.len(), 1);
    }

    #[test]
    fn role_gates_fold_into_sink_signals() {
        let catalog = Vec::new();
        let hints = TaintIrisNextAttackSurfaceHints {
            entry_points: Vec::new(),
            external_sinks: vec!["dlopen".to_string()],
            role_gates: vec!["has_privs_of_role".to_string()],
        };
        let cwe_focus = vec!["CWE-269".to_string()];
        let out = supplement_catalog_with_phantom_focus_entries(
            catalog,
            &hints,
            &no_signals(),
            &cwe_focus,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].sink_signals.contains(&"dlopen".to_string()));
        assert!(out[0]
            .sink_signals
            .contains(&"has_privs_of_role".to_string()));
    }
}

pub(crate) struct TaintIrisNextArtifactLoad {
    pub(crate) status: TaintIrisNextArtifactStatus,
    pub(crate) value: Option<Value>,
}

pub(crate) fn load_taint_iris_next_context(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    load_taint_iris_next_json_artifact(crate::context::context_snapshot_path(repo_root))
}

fn load_taint_iris_next_json_artifact(path: PathBuf) -> TaintIrisNextArtifactLoad {
    match crate::bounded_file::read_utf8_text(&path, 16 * 1024 * 1024) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(value) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: true,
                    path: Some(path.display().to_string()),
                    reason: "loaded".to_string(),
                },
                value: Some(value),
            },
            Err(error) => TaintIrisNextArtifactLoad {
                status: TaintIrisNextArtifactStatus {
                    ok: false,
                    path: Some(path.display().to_string()),
                    reason: format!("invalid JSON: {error}"),
                },
                value: None,
            },
        },
        Err(_) => TaintIrisNextArtifactLoad {
            status: TaintIrisNextArtifactStatus {
                ok: false,
                path: Some(path.display().to_string()),
                reason: "not found".to_string(),
            },
            value: None,
        },
    }
}

#[cfg(test)]
mod boost_with_discovered_signals_tests {
    use super::*;

    fn entry(
        cwe: &str,
        languages: Vec<&str>,
        sources: Vec<&str>,
        sinks: Vec<&str>,
    ) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: cwe.to_string(),
            taint_class: "test".to_string(),
            languages: languages.into_iter().map(String::from).collect(),
            source_signals: sources.into_iter().map(String::from).collect(),
            sink_signals: sinks.into_iter().map(String::from).collect(),
            sanitizer_signals: Vec::new(),
            structural_queries: Vec::new(),
            regex_markers: Vec::new(),
            score: 0,
            reasons: Vec::new(),
        }
    }

    fn signal(name: &str, cwe: &str, kind: &str, language: &str) -> DiscoveredSignal {
        DiscoveredSignal {
            name: name.to_string(),
            cwe: cwe.to_string(),
            kind: kind.to_string(),
            language: language.to_string(),
            marker: "test".to_string(),
            file: "f.c".to_string(),
            line: 1,
        }
    }

    #[test]
    fn splices_discovered_sources_into_matching_cwe_entry() {
        let catalog = vec![entry(
            "CWE-120",
            vec!["c"],
            vec!["PG_GETARG_TEXT_PP"],
            vec!["memcpy("],
        )];
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: vec![signal("pullf_read", "CWE-120", "source", "c")],
            sinks: Vec::new(),
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let out = boost_catalog_with_discovered_signals(catalog, &signals);
        let cwe120 = out.iter().find(|e| e.cwe == "CWE-120").unwrap();
        assert!(
            cwe120.source_signals.contains(&"pullf_read".to_string()),
            "got {:?}",
            cwe120.source_signals
        );
        assert!(cwe120
            .source_signals
            .contains(&"PG_GETARG_TEXT_PP".to_string()));
        assert_eq!(cwe120.score, 0, "bonus must NOT count spliced names");
    }

    #[test]
    fn pre_existing_overlap_still_earns_bonus() {
        let catalog = vec![entry(
            "CWE-120",
            vec!["c"],
            vec!["pullf_read"],
            vec!["memcpy("],
        )];
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: vec![signal("pullf_read", "CWE-120", "source", "c")],
            sinks: Vec::new(),
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let out = boost_catalog_with_discovered_signals(catalog, &signals);
        let cwe120 = out.iter().find(|e| e.cwe == "CWE-120").unwrap();
        assert_eq!(cwe120.score, 15, "PRE-existing overlap must still earn +15");
    }

    #[test]
    fn respects_language_match_for_splicing() {
        let catalog = vec![entry(
            "CWE-120",
            vec!["python"],
            vec!["existing_source"],
            vec!["existing_sink"],
        )];
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: vec![signal("pullf_read", "CWE-120", "source", "c")],
            sinks: Vec::new(),
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let out = boost_catalog_with_discovered_signals(catalog, &signals);
        let cwe120 = out.iter().find(|e| e.cwe == "CWE-120").unwrap();
        assert!(
            !cwe120.source_signals.contains(&"pullf_read".to_string()),
            "language gate must reject mismatched language"
        );
    }

    #[test]
    fn cross_cwe_does_not_splice() {
        let catalog = vec![entry(
            "CWE-94",
            vec!["c"],
            vec!["existing_source"],
            vec!["dlopen("],
        )];
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: vec![signal("pullf_read", "CWE-120", "source", "c")],
            sinks: Vec::new(),
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let out = boost_catalog_with_discovered_signals(catalog, &signals);
        let cwe94 = out.iter().find(|e| e.cwe == "CWE-94").unwrap();
        assert!(!cwe94.source_signals.contains(&"pullf_read".to_string()));
    }

    #[test]
    fn duplicate_discovery_records_do_not_starve_splice_budget() {
        // Discovery emits one record per occurrence, so a marker that
        // appears at 3 call sites lands in the per-CWE list 3 times.
        // The 8-slot budget MUST count unique names, not raw pushes —
        // otherwise the first frequently-occurring name eats every
        // slot and downstream names like pullf_read / pgp_mpi_read
        // are starved. Reproduces the pgcrypto bug where mbuf_*
        // duplicates squeezed pullf_read out of the CPG source set.
        let catalog = vec![entry(
            "CWE-120",
            vec!["c"],
            vec!["PG_GETARG_TEXT_PP"],
            vec!["memcpy("],
        )];
        // 9 records, only 3 unique names. If the splice counts pushes
        // instead of unique names, mbuf_append would consume 4 slots,
        // mbuf_avail would consume 4 more, and the 8-slot budget would
        // exhaust before pgp_mpi_read is reached.
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: vec![
                signal("mbuf_append", "CWE-120", "source", "c"),
                signal("mbuf_append", "CWE-120", "source", "c"),
                signal("mbuf_append", "CWE-120", "source", "c"),
                signal("mbuf_append", "CWE-120", "source", "c"),
                signal("mbuf_avail", "CWE-120", "source", "c"),
                signal("mbuf_avail", "CWE-120", "source", "c"),
                signal("mbuf_avail", "CWE-120", "source", "c"),
                signal("mbuf_avail", "CWE-120", "source", "c"),
                signal("pgp_mpi_read", "CWE-120", "source", "c"),
            ],
            sinks: Vec::new(),
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let out = boost_catalog_with_discovered_signals(catalog, &signals);
        let cwe120 = out.iter().find(|e| e.cwe == "CWE-120").unwrap();
        assert!(
            cwe120.source_signals.contains(&"pgp_mpi_read".to_string()),
            "pgp_mpi_read must fit in the splice budget despite mbuf_* duplicates; got {:?}",
            cwe120.source_signals
        );
        assert!(cwe120.source_signals.contains(&"mbuf_append".to_string()));
        assert!(cwe120.source_signals.contains(&"mbuf_avail".to_string()));
    }
}

#[cfg(test)]
mod catalog_regex_markers_for_discovery_tests {
    use super::*;

    fn regex_marker(
        pattern: &str,
        kind: &str,
        languages: Vec<&str>,
        marker: &str,
    ) -> TaintIrisNextRegexMarker {
        TaintIrisNextRegexMarker {
            pattern: pattern.to_string(),
            kind: kind.to_string(),
            languages: languages.into_iter().map(String::from).collect(),
            marker: marker.to_string(),
        }
    }

    fn entry_with_markers(
        cwe: &str,
        languages: Vec<&str>,
        markers: Vec<TaintIrisNextRegexMarker>,
    ) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: cwe.to_string(),
            taint_class: "test".to_string(),
            languages: languages.into_iter().map(String::from).collect(),
            source_signals: Vec::new(),
            sink_signals: Vec::new(),
            sanitizer_signals: Vec::new(),
            structural_queries: Vec::new(),
            regex_markers: markers,
            score: 0,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn lifts_catalog_markers_with_cwe_propagated() {
        let catalog = vec![entry_with_markers(
            "CWE-120",
            vec!["c"],
            vec![regex_marker(
                r"\b(pullf_[a-z_]+)\s*\(",
                "source",
                vec!["c"],
                "buffer.parser-read",
            )],
        )];
        let out = catalog_regex_markers_for_discovery(&catalog);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].cwe, "CWE-120");
        assert_eq!(out[0].kind, "source");
        assert_eq!(out[0].marker, "buffer.parser-read");
        assert_eq!(out[0].languages, vec!["c".to_string()]);
    }

    #[test]
    fn marker_languages_default_to_entry_languages_when_absent() {
        let catalog = vec![entry_with_markers(
            "CWE-120",
            vec!["c", "cpp"],
            vec![regex_marker(
                r"\bfoo\(",
                "source",
                vec![],
                "no-lang-on-marker",
            )],
        )];
        let out = catalog_regex_markers_for_discovery(&catalog);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].languages,
            vec!["c".to_string(), "cpp".to_string()],
            "marker should inherit entry's languages when its own list is empty"
        );
    }

    #[test]
    fn empty_marker_tag_falls_back_to_catalog_tag() {
        let catalog = vec![entry_with_markers(
            "CWE-120",
            vec!["c"],
            vec![regex_marker(r"\bfoo\(", "source", vec!["c"], "")],
        )];
        let out = catalog_regex_markers_for_discovery(&catalog);
        assert_eq!(out[0].marker, "catalog.cwe-120");
    }

    #[test]
    fn caps_total_marker_count_at_global_limit() {
        // Synthesize one entry with 100 markers — discovery should
        // truncate at CATALOG_MARKER_CAP (64) to bound rg-pass runtime.
        let many: Vec<_> = (0..100)
            .map(|i| regex_marker(&format!(r"\bfn_{i}\("), "source", vec!["c"], "test"))
            .collect();
        let catalog = vec![entry_with_markers("CWE-120", vec!["c"], many)];
        let out = catalog_regex_markers_for_discovery(&catalog);
        assert_eq!(out.len(), CATALOG_MARKER_CAP);
    }

    #[test]
    fn empty_catalog_returns_empty_vec() {
        assert!(catalog_regex_markers_for_discovery(&[]).is_empty());
    }

    #[test]
    fn entries_without_markers_contribute_nothing() {
        let catalog = vec![entry_with_markers("CWE-120", vec!["c"], vec![])];
        assert!(catalog_regex_markers_for_discovery(&catalog).is_empty());
    }
}

pub(crate) fn load_taint_iris_next_threat_model(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    load_taint_iris_next_json_artifact(
        crate::capabilities::threat_model::persistent_threat_model_path(repo_root),
    )
}
