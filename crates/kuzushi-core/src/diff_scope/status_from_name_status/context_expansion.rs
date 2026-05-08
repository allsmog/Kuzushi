use super::*;

pub(in crate::diff_scope) fn expand_diff_context(
    root: &Path,
    changed_files: &[ChangedFile],
    attack_surface: Option<&AttackSurfaceMap>,
) -> Result<Vec<DiffContext>> {
    let mut contexts = BTreeMap::new();
    for file in changed_files {
        insert_context(
            &mut contexts,
            DiffContext {
                kind: DiffContextKind::ChangedFile,
                path: file.path.clone(),
                line: file.changed_ranges.first().map(|range| range.start_line),
                detail: format!("{} changed in PR diff", file.path),
                reason: "changed_file".to_string(),
            },
        );
        if let Some(surface_map) = attack_surface {
            for surface in &surface_map.surfaces {
                if surface.path == file.path && surface_in_changed_context(surface.line, file) {
                    insert_context(
                        &mut contexts,
                        DiffContext {
                            kind: DiffContextKind::Route,
                            path: surface.path.clone(),
                            line: surface.line,
                            detail: surface.title.clone(),
                            reason: "route_or_attack_surface_near_diff".to_string(),
                        },
                    );
                }
            }
        }
        inspect_changed_source_context(root, file, &mut contexts)?;
    }
    Ok(contexts.into_values().collect())
}

pub(in crate::diff_scope) fn surface_in_changed_context(
    line: Option<u32>,
    file: &ChangedFile,
) -> bool {
    let Some(line) = line else {
        return true;
    };
    file.changed_ranges
        .iter()
        .any(|range| line_near_range(line, range, 25))
        || file.changed_ranges.is_empty()
}
