use super::*;
use crate::app::{RunResultDocumentRead, ViewHydrationKey};

pub(super) fn read_cached(
    app: &ShellApp,
    run_id: &str,
    projection: Option<&kuzushi_core::run_lifecycle::RunProjectionRead>,
) -> Option<RunResultDocumentRead> {
    let (producer, _, reference) =
        kuzushi_core::run_artifacts::single_result_artifact(&projection?.projection)?;
    let key = ViewHydrationKey::RunResultDocument {
        run_id: run_id.to_string(),
        producer,
        digest: reference.digest.to_string(),
    };
    match app
        .workbench_cache()
        .borrow()
        .cached_run_result_document(app.target()?, &key)
    {
        ViewDataState::Ready(state) => Some(state),
        _ => None,
    }
}
