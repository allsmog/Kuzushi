//! Engagement identity provenance for artifact headers.
//!
//! Chains and traces are transformations over one target revision and one
//! threat-model revision — the stable center of the artifact graph. This
//! line names both, but only the parts the cached git metadata and the
//! persisted document actually carry; callers keep their count-based copy
//! as the degraded form when neither is known.

use crate::ShellApp;

/// e.g. `target kuzushi@1a2b3c4d+dirty · threat model @9f8e7d6c`.
pub(super) fn engagement_identity_line(app: &ShellApp) -> Option<String> {
    let parts: Vec<String> = [target_identity(app), threat_model_identity(app)]
        .into_iter()
        .flatten()
        .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Target directory name plus its cached git revision when the workbench
/// cache has one; never a fresh `git` subprocess on the render path.
fn target_identity(app: &ShellApp) -> Option<String> {
    let target = app.target()?;
    let name = target.file_name()?.to_string_lossy().to_string();
    let revision = match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(app.target())
    {
        crate::app::ViewDataState::Ready(Some(git)) => {
            format!("@{}{}", short_revision(&git.sha), dirty_suffix(git.dirty))
        }
        _ => String::new(),
    };
    Some(format!("target {name}{revision}"))
}

fn threat_model_identity(app: &ShellApp) -> Option<String> {
    let doc = crate::ui_view_models::threat_model_doc(app)?;
    let (revision, dirty) = threat_model_doc_revision(&doc)?;
    Some(format!(
        "threat model @{}{}",
        short_revision(&revision),
        dirty_suffix(dirty)
    ))
}

/// The revision the persisted threat-model document was built against
/// (`provenance.revision`, stamped by the staged pipeline), if any.
pub(super) fn threat_model_doc_revision(doc: &serde_json::Value) -> Option<(String, bool)> {
    let revision = doc
        .pointer("/provenance/revision")?
        .as_str()
        .filter(|revision| !revision.is_empty())?;
    let dirty = doc
        .pointer("/provenance/revisionDirty")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some((revision.to_string(), dirty))
}

pub(super) fn short_revision(sha: &str) -> String {
    sha.chars().take(8).collect()
}

fn dirty_suffix(dirty: bool) -> &'static str {
    if dirty {
        "+dirty"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn doc_revision_reads_the_stamped_provenance_only() {
        let doc = json!({
            "provenance": {"revision": "a1b2c3d4e5f60718", "revisionDirty": true}
        });
        assert_eq!(
            threat_model_doc_revision(&doc),
            Some(("a1b2c3d4e5f60718".to_string(), true))
        );
        assert_eq!(threat_model_doc_revision(&json!({})), None);
        assert_eq!(
            threat_model_doc_revision(&json!({"provenance": {"revision": ""}})),
            None,
            "an empty revision claims nothing"
        );
    }

    #[test]
    fn short_revision_truncates_without_inventing_padding() {
        assert_eq!(short_revision("a1b2c3d4e5f60718"), "a1b2c3d4");
        assert_eq!(short_revision("abc"), "abc");
    }
}
