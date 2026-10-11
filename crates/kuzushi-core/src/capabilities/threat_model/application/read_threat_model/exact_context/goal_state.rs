use super::*;
use crate::capabilities::campaign::{load_brief, BriefReference};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordedIntent {
    schema_version: u32,
    reference: BriefReference,
    text_bytes: usize,
    purpose: String,
    source_evidence: bool,
    finding_authority: bool,
}

pub(crate) fn inspect(root: &Path, document: &Value) -> Value {
    let Some(recorded) = document.pointer("/provenance/operatorIntent") else {
        return json!({"schemaVersion":1,"status":"absent","message":"No operator goal guidance is recorded for this context."});
    };
    match inspect_recorded(root, recorded) {
        Ok(value) => value,
        Err(error) => {
            json!({"schemaVersion":1,"status":"unavailable","message":format!("Recorded goal guidance is unavailable: {error}. No current goal was substituted."),
            "modelUseVerified":false,"sourceEvidence":false,"findingAuthority":false})
        }
    }
}

fn inspect_recorded(root: &Path, value: &Value) -> Result<Value> {
    let intent: RecordedIntent =
        serde_json::from_value(value.clone()).context("Goal provenance is malformed")?;
    anyhow::ensure!(
        intent.schema_version == 1 && !intent.source_evidence && !intent.finding_authority,
        "Goal provenance cannot claim source evidence or finding authority"
    );
    let brief = load_brief(root, &intent.reference)?;
    anyhow::ensure!(
        intent.text_bytes == brief.document.text.len(),
        "Recorded goal text byte count does not match its immutable revision"
    );
    Ok(
        json!({"schemaVersion":1,"status":"recorded","reference":intent.reference,"textBytes":intent.text_bytes,
        "text":brief.document.text,"purpose":intent.purpose,"referenceAuthenticated":true,"modelUseVerified":false,
        "sourceEvidence":false,"findingAuthority":false,
        "message":"The exact saved goal reference is authenticated. This read does not independently verify model use or validate context claims."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};

    fn brief(root: &Path, revision: u32, text: &str) -> Value {
        let workspace = WorkspaceTarget::new(root).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        ModuleRegistry::with_v2_builtins()
            .execute_tool(
                "campaign:brief",
                json!({"mode":"save","expectedRevision":revision,"text":text}),
                &ctx,
            )
            .unwrap()["data"]["brief"]
            .clone()
    }

    fn context(goal: &Value) -> Value {
        json!({"provenance":{"operatorIntent":{"schemaVersion":1,"reference":goal["reference"],
            "textBytes":goal["document"]["text"].as_str().unwrap().len(),"purpose":"architecture priorities and open questions",
            "sourceEvidence":false,"findingAuthority":false}}})
    }

    #[test]
    fn old_goal_text_is_authenticated_without_claiming_model_use_or_selecting_current_head() {
        let root = tempfile::tempdir().unwrap();
        let first = brief(root.path(), 0, "Original priorities\n東京 owner questions.");
        let second = brief(root.path(), 1, "New priorities");
        let state = inspect(root.path(), &context(&first));
        assert_eq!(state["status"], "recorded");
        assert_eq!(state["text"], first["document"]["text"]);
        assert_eq!(state["reference"], first["reference"]);
        assert_eq!(state["referenceAuthenticated"], true);
        assert_eq!(state["modelUseVerified"], false);
        assert_eq!(
            crate::capabilities::campaign::load_current_brief(root.path(), "repository")
                .unwrap()
                .unwrap()
                .reference,
            serde_json::from_value::<BriefReference>(second["reference"].clone()).unwrap()
        );
    }

    #[test]
    fn invalid_or_missing_guidance_is_disclosed_without_current_goal_substitution() {
        let root = tempfile::tempdir().unwrap();
        let first = brief(root.path(), 0, "Original priorities");
        assert_eq!(inspect(root.path(), &json!({}))["status"], "absent");
        for (key, value) in [
            ("textBytes", json!(0)),
            ("sourceEvidence", json!(true)),
            ("findingAuthority", json!(true)),
            ("schemaVersion", json!(2)),
        ] {
            let mut document = context(&first);
            document["provenance"]["operatorIntent"][key] = value;
            assert_eq!(inspect(root.path(), &document)["status"], "unavailable");
        }
        std::fs::remove_file(
            root.path()
                .join(".kuzushi/v3/investigation-briefs/repository/revisions/1.json"),
        )
        .unwrap();
        let state = inspect(root.path(), &context(&first));
        assert_eq!(state["status"], "unavailable");
        assert!(state.get("text").is_none());
        assert_eq!(state["modelUseVerified"], false);
    }
}
