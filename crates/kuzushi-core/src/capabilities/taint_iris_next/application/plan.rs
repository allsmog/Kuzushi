use super::*;

pub(crate) fn build_taint_iris_next_plan(
    target: &Path,
    options: TaintIrisNextInput,
) -> Result<TaintIrisNextPlan> {
    let repo_root = target.to_path_buf();
    let context = load_taint_iris_next_context(&repo_root);
    let threat_model = load_taint_iris_next_threat_model(&repo_root);
    let mut languages = options.languages.clone();
    languages.extend(taint_iris_next_context_languages(context.value.as_ref()));
    languages.extend(detect_taint_iris_next_languages(target)?);
    languages = languages
        .into_iter()
        .map(|language| normalize_taint_next_language(&language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let threat_cwes = collect_taint_iris_next_cwes(threat_model.value.as_ref());
    let context_keywords = taint_iris_next_context_keywords(context.value.as_ref(), target)?;
    // Merge operator-supplied entries (from threat-intel) on top of
    // the hardcoded catalog before truncation. Extras are scored at
    // 200 by the adapter so they survive truncation; the merged list
    // re-sorts so a high-context-overlap built-in can still beat a
    // low-priority extra. De-dup by `cwe + taint_class`: operator
    // entries win because they typically carry richer source/sink
    // signals than the generic built-ins.
    let mut ranked = rank_taint_iris_next_catalog(&languages, &threat_cwes, &context_keywords);
    if !options.extra_catalog_entries.is_empty() {
        ranked = merge_taint_iris_next_extra_entries(ranked, &options.extra_catalog_entries);
    }
    let catalog = ranked
        .into_iter()
        .take(options.caps.max_catalog_entries)
        .collect::<Vec<_>>();
    let structural_queries = build_taint_iris_next_structural_queries(&catalog);
    let prompt_catalog = render_taint_iris_next_catalog(&catalog);
    let backend = choose_taint_iris_next_backend(&options.backend, &repo_root);

    Ok(TaintIrisNextPlan {
        target: target.to_path_buf(),
        scan_root: target.to_path_buf(),
        repo_root,
        mode: options.mode,
        caps: options.caps,
        languages,
        context_status: context.status,
        threat_model_status: threat_model.status,
        repo_context: context.value,
        threat_model: threat_model.value,
        catalog,
        structural_queries,
        prompt_catalog,
        backend,
        max_budget_usd: options.max_budget_usd,
    })
}

pub(crate) struct TaintIrisNextArtifactLoad {
    pub(crate) status: TaintIrisNextArtifactStatus,
    pub(crate) value: Option<Value>,
}

pub(crate) fn load_taint_iris_next_context(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    let path = repo_root.join(".kuzushi").join("context-snapshot.json");
    match fs::read_to_string(&path) {
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

pub(crate) fn load_taint_iris_next_threat_model(repo_root: &Path) -> TaintIrisNextArtifactLoad {
    let path = repo_root.join(".kuzushi").join("threat-model.json");
    match fs::read_to_string(&path) {
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
