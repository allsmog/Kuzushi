use super::*;

pub(crate) fn codeindex_has_joern_backend(facade: &kuzushi_codeindex::IndexFacade) -> bool {
    facade
        .live_backends()
        .iter()
        .any(|backend| matches!(backend, kuzushi_codeindex::Backend::Joern))
}

pub(crate) async fn indexed_ffi_files(
    facade: &mut kuzushi_codeindex::IndexFacade,
) -> BTreeSet<String> {
    facade
        .ffi_boundaries()
        .await
        .map(|value| ffi_files_from_index_value(&value))
        .unwrap_or_default()
}

pub(crate) fn ffi_files_from_index_value(value: &Value) -> BTreeSet<String> {
    value
        .get("boundaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("file").and_then(Value::as_str).map(str::to_string))
        .collect()
}

pub(crate) async fn index_score_surface(
    facade: &mut kuzushi_codeindex::IndexFacade,
    ffi_set: &BTreeSet<String>,
    mut surface: RankedSystemsSurface,
) -> RankedSystemsSurface {
    apply_indexed_unsafe_score(facade, &mut surface).await;
    apply_indexed_ffi_score(ffi_set, &mut surface);
    apply_indexed_taint_score(facade, &mut surface).await;
    surface
}

pub(crate) async fn apply_indexed_unsafe_score(
    facade: &mut kuzushi_codeindex::IndexFacade,
    surface: &mut RankedSystemsSurface,
) {
    if !is_native_unsafe_surface(surface) {
        return;
    }
    let Ok(value) = facade.unsafe_blocks(Some(&surface.file_path)).await else {
        return;
    };
    if let Some((n, bump)) = unsafe_block_bump(&value) {
        surface.score += bump;
        surface
            .reasons
            .insert(0, format!("codeindex: {n} unsafe block(s) (+{bump})"));
    }
}

pub(crate) fn is_native_unsafe_surface(surface: &RankedSystemsSurface) -> bool {
    surface.kind == "unsafe-region" && has_native_source_extension(&surface.file_path)
}

pub(crate) fn has_native_source_extension(file_path: &str) -> bool {
    let extension = Path::new(file_path)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    ["rs", "c", "cpp", "cc"].contains(&extension.as_str())
}

pub(crate) fn unsafe_block_bump(value: &Value) -> Option<(usize, i64)> {
    let n = value.get("blocks").and_then(Value::as_array)?.len();
    (n > 0).then_some((n, (n.min(5) as i64) * 10))
}

pub(crate) fn apply_indexed_ffi_score(
    ffi_set: &BTreeSet<String>,
    surface: &mut RankedSystemsSurface,
) {
    if !has_indexed_ffi_signal(ffi_set, surface) {
        return;
    }
    surface.score += 8;
    surface
        .reasons
        .insert(0, "codeindex: FFI boundary present (+8)".to_string());
}

pub(crate) fn has_indexed_ffi_signal(
    ffi_set: &BTreeSet<String>,
    surface: &RankedSystemsSurface,
) -> bool {
    [
        surface.kind == "ffi-boundary",
        surface.domains.iter().any(|domain| domain == "ffi"),
        ffi_set.contains(&surface.file_path),
    ]
    .into_iter()
    .any(|matched| matched)
}

pub(crate) async fn apply_indexed_taint_score(
    facade: &mut kuzushi_codeindex::IndexFacade,
    surface: &mut RankedSystemsSurface,
) {
    if !indexed_taint_path_found(facade, surface).await {
        return;
    }
    surface.score += 15;
    surface
        .reasons
        .insert(0, "codeindex: taint path reachable (+15)".to_string());
}
