use super::prelude::*;
use super::*;

pub(in crate::modules) fn build_taint_iris_next_plan(
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
    let catalog = rank_taint_iris_next_catalog(&languages, &threat_cwes, &context_keywords)
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

pub(in crate::modules) struct TaintIrisNextArtifactLoad {
    pub(in crate::modules) status: TaintIrisNextArtifactStatus,
    pub(in crate::modules) value: Option<Value>,
}

pub(in crate::modules) fn load_taint_iris_next_context(
    repo_root: &Path,
) -> TaintIrisNextArtifactLoad {
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

pub(in crate::modules) fn load_taint_iris_next_threat_model(
    repo_root: &Path,
) -> TaintIrisNextArtifactLoad {
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
