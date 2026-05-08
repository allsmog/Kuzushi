use super::prelude::*;
use super::*;

pub(crate) fn gather_systems_context(
    target: &Path,
    options: &SystemsHuntInput,
) -> Result<SystemsContextOutput> {
    let inventory = collect_inventory(target, options.max_files, options.head_bytes)?;
    let mut by_file: BTreeMap<String, SurfaceAccumulator> = BTreeMap::new();

    for (file_path, body) in &inventory {
        for (idx, line) in body.lines().enumerate() {
            let line_number = (idx + 1) as u32;
            let signals = classify_line(line);
            if signals.is_empty() {
                continue;
            }
            let key = file_path.clone();
            let accumulator = by_file.entry(key.clone()).or_insert_with(|| {
                SurfaceAccumulator::new(file_path.clone(), infer_kind(file_path, line), line_number)
            });
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
            for field in attacker_fields(line) {
                accumulator.attacker_controlled_fields.insert(field);
            }
            for hardening in hardening_signals(line) {
                accumulator.hardening_signals.insert(hardening);
            }
        }
    }

    let mut surfaces = by_file
        .into_values()
        .map(SurfaceAccumulator::finish)
        .collect::<Vec<_>>();
    // Pre-sort: the index-augmentation step only queries the top-N
    // surfaces (most expensive backend calls otherwise dominate cost
    // on large repos), so sort first, augment, then re-sort.
    surfaces.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
    });

    // Block-on the async index augmentation. Failures (no joern,
    // network error, …) leave surfaces unchanged.
    let augment_count = surfaces.len().min(options.max_surfaces.saturating_mul(2));
    let to_augment = surfaces
        .drain(..augment_count.min(surfaces.len()))
        .collect();
    let augmented = score_with_index_blocking(to_augment);
    let mut surfaces: Vec<RankedSystemsSurface> = augmented.into_iter().chain(surfaces).collect();
    // Re-sort after augmentation: index bumps may have re-ordered the
    // top of the list.
    surfaces.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.start_line.cmp(&right.start_line))
    });
    surfaces.truncate(options.max_surfaces);

    let surface_packs = surfaces
        .iter()
        .map(|surface| build_surface_pack(target, surface))
        .collect::<Result<Vec<_>>>()?;
    let codeql_db_path = resolve_codeql_db_path(target);
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

pub(crate) fn score_with_index_blocking(
    surfaces: Vec<RankedSystemsSurface>,
) -> Vec<RankedSystemsSurface> {
    fn run(surfaces: Vec<RankedSystemsSurface>) -> Vec<RankedSystemsSurface> {
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(score_with_index(surfaces)),
            Err(_) => Vec::new(),
        }
    }

    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(move || run(surfaces))
            .join()
            .unwrap_or_default()
    } else {
        run(surfaces)
    }
}
