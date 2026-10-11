use super::*;
use serde_json::{json, Value};

pub(in crate::capabilities::campaign) fn prepare_guided_input(
    root: &Path,
    input: &Value,
    tool: &str,
) -> Result<Value> {
    let mut context = input
        .get("contextInput")
        .cloned()
        .context("contextInput is required")?;
    anyhow::ensure!(
        context.get("operatorBriefRef").is_none(),
        "Select briefRef and useBriefGuidance explicitly; contextInput cannot select another goal"
    );
    if input["useBriefGuidance"] != true {
        return Ok(context);
    }
    anyhow::ensure!(tool == "threat-model:build", "Goal guidance supports repository and file-group context builds; other actions retain their own explicit guidance");
    let brief = from_input(root, input)?
        .context("Select an exact briefRef before enabling goal guidance")?;
    context
        .as_object_mut()
        .context("contextInput must be an object")?
        .insert("operatorBriefRef".into(), json!(brief.reference));
    Ok(context)
}

pub(in crate::capabilities::campaign) fn guidance_receipt(
    plan: &Value,
) -> Result<Option<BriefGuidanceV1>> {
    if plan["kind"] != "context-study" {
        return Ok(None);
    }
    let Some(reference) = plan["jobs"]
        .as_array()
        .and_then(|jobs| jobs.last())
        .and_then(|job| job["input"].get("operatorBriefRef"))
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        plan["tool"] == "threat-model:build",
        "Operator goal guidance requires a context build"
    );
    let brief: BriefRevision = serde_json::from_value(plan["investigationBrief"].clone())
        .context("Guided context plan requires its frozen investigation brief")?;
    anyhow::ensure!(
        reference == &json!(brief.reference),
        "Context goal differs from the plan's reviewed brief"
    );
    Ok(Some(BriefGuidanceV1 {
        schema_version: 1,
        reference: brief.reference,
        text_bytes: brief.document.text.len(),
        text: brief.document.text,
    }))
}
