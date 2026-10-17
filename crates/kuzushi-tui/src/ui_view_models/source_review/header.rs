use crate::app::source_review::SourceReviewForm;
use crate::renderer::shared::text::{fit, fit_path};
use kuzushi_core::run_lifecycle::SafeText;
use serde_json::Value;

/// Keep the judged finding and captured source visible independently of paging.
pub(crate) fn source_review_header_lines(form: &SourceReviewForm, width: usize) -> Vec<String> {
    vec![
        fit(&SafeText::condensed_line(&form.title).to_string(), width),
        fit_path(
            &SafeText::operator_visible(format!("{}:{}", form.file, form.line)).to_string(),
            width,
        ),
        fit(&captured_identity(form.capture.as_ref()), width),
    ]
}

pub(super) fn captured_identity(capture: Option<&Value>) -> String {
    let Some(capture) = capture else {
        return "Source not captured".into();
    };
    let source = &capture["reviewedSource"];
    if let Some(sha) = hex_identity(&source["sourceGit"]["sha"]) {
        return format!(
            "Captured SHA {} · {}",
            &sha[..12],
            checkout_state(&source["sourceGit"]["dirty"])
        );
    }
    match hex_identity(&source["treeHash"]).filter(|hash| hash.len() == 64) {
        Some(hash) => format!("Content {} · Git unknown", &hash[..12]),
        None => "Source identity unavailable".into(),
    }
}

fn hex_identity(value: &Value) -> Option<&str> {
    value.as_str().filter(|hash| {
        matches!(hash.len(), 40 | 64) && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn checkout_state(dirty: &Value) -> &'static str {
    match dirty.as_bool() {
        Some(true) => "dirty",
        Some(false) => "clean",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests;
