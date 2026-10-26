use super::*;

pub(crate) struct ContextCatalog {
    pub(crate) rows: Vec<ContextRow>,
    pub(crate) status: String,
    pub(super) membership_known: bool,
}

pub(crate) struct ContextRow {
    pub(crate) reference: Option<ThreatModelRef>,
    pub(crate) label: String,
    pub(crate) details: Vec<String>,
    pub(crate) copy_label: Option<String>,
}

pub(crate) fn context_identity(rows: &[ContextRow], reference: Option<&ThreatModelRef>) -> String {
    if let Some(row) = rows.iter().find(|row| row.reference.as_ref() == reference) {
        return format!("Context: {}", row.label);
    }
    match reference {
        Some(reference) => format!("Context: {}", reference.revision_id),
        None => "Context: no revision selected".into(),
    }
}

pub(crate) fn context_catalog(app: &ShellApp) -> ContextCatalog {
    let mut catalog = ContextCatalog {
        rows: vec![initial_context_row(app)],
        status: String::new(),
        membership_known: false,
    };
    let state = app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(app.target());
    match state {
        ViewDataState::Ready(ThreatModelStoreState::Ready { manifest, .. }) => {
            append_revisions(&mut catalog, &manifest)
        }
        ViewDataState::Ready(ThreatModelStoreState::Invalid(error)) => {
            catalog.status = format!("Context catalog unavailable: {error}")
        }
        ViewDataState::Ready(ThreatModelStoreState::Legacy) => catalog.status =
            "No immutable revisions. Build or import context from Map, then return to this study."
                .into(),
        _ => catalog.status = "Loading context revisions…".into(),
    }
    explain_regeneration_catalog(app, &mut catalog);
    catalog
}

fn explain_regeneration_catalog(app: &ShellApp, catalog: &mut ContextCatalog) {
    if catalog.membership_known
        && app
            .study_context_picker()
            .is_some_and(|p| p.regeneration_entry)
    {
        catalog.status = format!(
            "{} saved revisions. Choose the parent for an inactive copy.",
            catalog.rows.len().saturating_sub(1)
        );
    }
}

fn initial_context_row(app: &ShellApp) -> ContextRow {
    if app
        .study_context_picker()
        .is_some_and(|picker| picker.regeneration_entry)
    {
        return ContextRow { reference: None, label: "Choose a saved revision".into(), copy_label: None,
            details: vec!["Select a revision, press Enter to inspect it, then e to choose text for regeneration. Planning, allowance approval and execution are separate. No request has started.".into()] };
    }
    omission_row()
}

fn omission_row() -> ContextRow {
    ContextRow {
        reference: None, label: "Omit threat-model context".into(), copy_label:None,
        details: vec!["Discovery will receive no threat-model document for this selection. Omission does not establish finding verdicts or repository coverage.".into(), "a saves this explicit omission for the selected study or boundary. No scan starts.".into()],
    }
}

fn append_revisions(catalog: &mut ContextCatalog, manifest: &ThreatModelManifest) {
    catalog.membership_known = true;
    for model in &manifest.models {
        for (index, revision) in model.revisions.iter().enumerate().rev() {
            let scope = revision.scope.as_ref().unwrap_or(&model.scope);
            catalog.rows.push(ContextRow {
                reference: Some(ThreatModelRef {
                    model_id: model.model_id.clone(),
                    revision_id: revision.revision_id.clone(),
                    sha256: revision.sha256.clone(),
                }),
                label: format!("{} · revision {}", model.label, index + 1),
                copy_label: Some(format!("{} · edited", model.label)),
                details: vec![
                    format!("{} · {}", model.label, model.methodology),
                    format!("Scope: {}", scope.rel_path.display()),
                    format!("Recorded source revision: {}", scope.target_revision),
                    format!(
                        "Last recorded check: {}",
                        revision
                            .verification
                            .as_ref()
                            .map_or("unverified", |check| check.verdict.as_str())
                    ),
                    format!("Saved: {}", context_age(&revision.created_at)),
                    format!("Context digest: {}", revision.sha256),
                ],
            });
        }
    }
    catalog.status = format!(
        "{} immutable revisions. Selection applies only to this study.",
        catalog.rows.len() - 1
    );
}

pub(super) fn context_age(recorded: &str) -> String {
    let seconds = recorded
        .parse::<u64>()
        .ok()
        .or_else(|| kuzushi_core::session_transcript::unix_seconds_from_timestamp(recorded));
    seconds
        .and_then(|seconds| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .and_then(|then| super::super::format_relative_age(SystemTime::now(), then))
        .unwrap_or_else(|| format!("unavailable ({recorded})"))
}
