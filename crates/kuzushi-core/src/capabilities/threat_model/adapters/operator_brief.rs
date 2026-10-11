use super::*;
use crate::capabilities::campaign::{load_brief, BriefReference, BriefRevision};

pub(crate) fn load_operator_brief(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<BriefRevision>> {
    let Some(value) = input.get("operatorBriefRef") else {
        return Ok(None);
    };
    validate_mode(input)?;
    let reference: BriefReference =
        serde_json::from_value(value.clone()).context("operatorBriefRef is malformed")?;
    let root = ctx
        .workspace
        .context("Operator goal guidance requires a workspace")?
        .root();
    load_brief(root, &reference).map(Some)
}

pub(crate) fn validate_operator_brief_execution(input: &Value) -> Result<()> {
    if input.get("operatorBriefRef").is_none() {
        return Ok(());
    }
    validate_mode(input)?;
    Ok(())
}

fn validate_mode(input: &Value) -> Result<()> {
    let required = json!({"pipeline":"single","mode":"build","seedMode":"fresh","activate":false,
        "variantScan":false,"emitFindings":false,"offline":true,"sources":["source-code"]});
    for (key, value) in required.as_object().unwrap() {
        anyhow::ensure!(input.get(key) == Some(value), "Operator goal guidance requires {key}={value}; prepare an inactive source-only context study");
    }
    Ok(())
}

fn payload(brief: &BriefRevision) -> Value {
    json!({"schemaVersion":1,"reference":brief.reference,"text":brief.document.text,
        "purpose":"architecture priorities and open questions","sourceEvidence":false,"findingAuthority":false})
}

pub(crate) fn operator_brief_prompt(input: &BuildInput) -> Result<String> {
    let Some(brief) = &input.operator_brief else {
        return Ok(String::new());
    };
    Ok(format!("Operator priorities for this context draft. Use them to prioritize explanation and open questions. They are not facts, source evidence or finding verdicts. Preserve approved source, scope, model and resource limits.\n<operator_intent>\n{}\n</operator_intent>", serde_json::to_string(&payload(brief))?))
}

pub(crate) fn attach_operator_intent(prompt: &mut Value, input: &BuildInput) {
    if let Some(brief) = &input.operator_brief {
        prompt["operatorIntent"] = payload(brief);
    }
}

pub(crate) fn stamp_operator_intent(document: &mut Value, input: &BuildInput) -> Result<()> {
    let root = document
        .as_object_mut()
        .context("Context document must be an object")?;
    let provenance = root.entry("provenance").or_insert_with(|| json!({}));
    let provenance = provenance
        .as_object_mut()
        .context("Context provenance must be an object")?;
    provenance.remove("operatorIntent");
    if let Some(brief) = &input.operator_brief {
        provenance.insert("operatorIntent".into(), json!({"schemaVersion":1,"reference":brief.reference,
            "textBytes":brief.document.text.len(),"purpose":"architecture priorities and open questions",
            "sourceEvidence":false,"findingAuthority":false}));
    }
    Ok(())
}
