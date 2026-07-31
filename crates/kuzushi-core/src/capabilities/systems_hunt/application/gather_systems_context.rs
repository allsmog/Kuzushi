use super::*;

pub(crate) fn gather_systems_context(
    target: &Path,
    options: &SystemsHuntInput,
) -> Result<SystemsContextOutput> {
    let inventory = collect_production_inventory(target, options)?;
    let surfaces = ranked_system_surfaces(&inventory, options.max_surfaces);
    let surface_packs = surfaces
        .iter()
        .map(|surface| build_surface_pack(target, surface))
        .collect::<Result<Vec<_>>>()?;
    let codeql_db_path = resolve_codeql_db_path(target)?;
    Ok(SystemsContextOutput {
        surfaces,
        surface_packs,
        metadata: SystemsContextMetadata {
            codeql_available: codeql_db_path.is_some(),
            codeql_db_path: codeql_db_path.map(|path| path.display().to_string()),
            bash_probing_used: false,
        },
    })
}

/// Read-safe systems surface ranking: walk the production inventory and score
/// surfaces with the deterministic classifier only. Unlike
/// [`ranked_system_surfaces`], it never calls `score_with_index_blocking`,
/// which would spawn the cpg MCP server and implicitly build `.kuzushi/cpg-rs`.
/// This is the only systems ranker a `ToolEffect::Read` tool may fold.
pub(crate) fn rank_systems_surfaces_lite(
    target: &Path,
    max: usize,
) -> Result<Vec<RankedSystemsSurface>> {
    let options = SystemsHuntInput::from_tool_input(&json!({ "maxSurfaces": max }))?;
    let inventory = collect_production_inventory(target, &options)?;
    let mut surfaces = collect_system_surfaces(&inventory);
    sort_system_surfaces(&mut surfaces);
    surfaces.truncate(max);
    Ok(surfaces)
}

fn ranked_system_surfaces(
    inventory: &[(String, String)],
    max_surfaces: usize,
) -> Vec<RankedSystemsSurface> {
    let mut surfaces = collect_system_surfaces(inventory);
    sort_system_surfaces(&mut surfaces);
    let augment_count = surfaces.len().min(max_surfaces.saturating_mul(2));
    let to_augment = surfaces.drain(..augment_count).collect();
    let mut surfaces = score_with_index_blocking(to_augment)
        .into_iter()
        .chain(surfaces)
        .collect::<Vec<_>>();
    sort_system_surfaces(&mut surfaces);
    surfaces.truncate(max_surfaces);
    surfaces
}

fn collect_system_surfaces(inventory: &[(String, String)]) -> Vec<RankedSystemsSurface> {
    let mut by_file: BTreeMap<String, SurfaceAccumulator> = BTreeMap::new();
    for (file_path, body) in inventory {
        collect_file_surfaces(&mut by_file, file_path, body);
    }
    by_file
        .into_values()
        .map(SurfaceAccumulator::finish)
        .collect()
}

fn collect_file_surfaces(
    by_file: &mut BTreeMap<String, SurfaceAccumulator>,
    file_path: &str,
    body: &str,
) {
    for (idx, line) in body.lines().enumerate() {
        let line_number = (idx + 1) as u32;
        let signals = classify_line(line);
        if signals.is_empty() {
            continue;
        }
        let accumulator = by_file.entry(file_path.to_string()).or_insert_with(|| {
            SurfaceAccumulator::new(
                file_path.to_string(),
                infer_kind(file_path, line),
                line_number,
            )
        });
        record_surface_signals(accumulator, line, line_number, signals);
    }
}

fn record_surface_signals(
    accumulator: &mut SurfaceAccumulator,
    line: &str,
    line_number: u32,
    signals: Vec<(&'static str, &'static str, i64)>,
) {
    accumulator.start_line = accumulator.start_line.min(line_number);
    for (domain, reason, weight) in signals {
        accumulator.score += weight;
        accumulator.domains.insert(domain.to_string());
        accumulator.reasons.insert(reason.to_string());
        accumulator.evidence.push(SystemsSurfaceSignal {
            domain: domain.to_string(),
            line_number,
            line_content: trim_line(line),
            reason: reason.to_string(),
        });
    }
    accumulator
        .attacker_controlled_fields
        .extend(attacker_fields(line));
    accumulator
        .hardening_signals
        .extend(hardening_signals(line));
}

fn sort_system_surfaces(surfaces: &mut [RankedSystemsSurface]) {
    surfaces.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
    });
}

pub(crate) fn score_with_index_blocking(
    surfaces: Vec<RankedSystemsSurface>,
) -> Vec<RankedSystemsSurface> {
    fn run(surfaces: Vec<RankedSystemsSurface>) -> Vec<RankedSystemsSurface> {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return surfaces,
        };
        runtime.block_on(score_with_index(surfaces))
    }

    if tokio::runtime::Handle::try_current().is_ok() {
        let fallback = surfaces.clone();
        std::thread::spawn(move || run(surfaces))
            .join()
            .unwrap_or(fallback)
    } else {
        run(surfaces)
    }
}
