//! Preserve literal filenames, recorded limits, and inherited-context identity.
use super::*;

pub(super) fn lines(receipt: &Value) -> Vec<String> {
    let source = &receipt["sourceEvidence"];
    let mut lines = membership_lines(receipt);
    lines.extend([
        format!(
            "Source limits: {} bytes · {} files · {} bytes supplied",
            count(&source["byteBudget"]),
            count(&source["fileLimit"]),
            count(&source["readBytes"])
        ),
        format!(
            "Source omissions: {}",
            source
                .get("omissions")
                .map(Value::to_string)
                .unwrap_or_else(|| "unrecorded".into())
        ),
    ]);
    if receipt["completeRepositoryCoverage"] == true {
        lines.push("Recorded complete-coverage claim is unverified; complete repository coverage is not established here.".into());
    }
    lines.extend(
        source["files"]
            .as_array()
            .into_iter()
            .flatten()
            .map(file_line),
    );
    lines
}

fn membership_lines(receipt: &Value) -> Vec<String> {
    vec![
        format!(
            "Membership: {} discovery · {} shared-context files",
            count(&receipt["discoveryFileCount"]),
            count(&receipt["sharedFileCount"])
        ),
        format!(
            "Inherited architecture revision: {}",
            receipt["inheritedContextRef"]["revisionId"]
                .as_str()
                .unwrap_or("unrecorded")
        ),
        "Inherited text supplies context. The listed excerpts supply source evidence.".into(),
    ]
}

fn file_line(file: &Value) -> String {
    let path = file
        .get("path")
        .map(Value::to_string)
        .unwrap_or_else(|| "unrecorded path".into());
    let role = file["scopeRole"].as_str().unwrap_or("role unrecorded");
    format!(
        "  {path} · {role} · omitted lines: {} · excluded test lines: {}",
        count(&file["omittedLines"]),
        count(&file["excludedTestLines"])
    )
}
