use super::*;

pub(super) fn validate(input: &Value) -> Result<()> {
    let required = json!({"pipeline":"single","mode":"build","seedMode":"fresh","newModel":true,"activate":false,"sources":["source-code"],"variantScan":false,"emitFindings":false,"offline":true,"preserveUserEdits":false});
    for (key, value) in required.as_object().unwrap() {
        anyhow::ensure!(input.get(key)==Some(value), "File-group context requires {key}={value}; prepare a bounded campaign:context-study draft");
    }
    for key in [
        "scope",
        "modelId",
        "seed",
        "designDocs",
        "vulnsFile",
        "advisoryFixtures",
        "outputDir",
    ] {
        anyhow::ensure!(
            input.get(key).is_none(),
            "File-group context cannot combine with {key}"
        );
    }
    Ok(())
}

pub(super) fn validate_citations(value: &Value, references: &BTreeSet<String>) -> Result<()> {
    match value {
        Value::Object(object) => {
            validate_object_citations(object, references)?;
        }
        Value::Array(rows) => {
            for child in rows {
                validate_citations(child, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_reference_rows(rows: &Value, references: &BTreeSet<String>) -> Result<()> {
    for row in rows.as_array().context("sourceRefs must be an array")? {
        let reference = row
            .as_str()
            .context("Context sourceRefs must be literal file:line strings")?;
        anyhow::ensure!(references.contains(reference), "Context citation {reference} was not supplied in this accepted group; no repair request was made");
    }
    Ok(())
}

fn validate_object_citations(
    object: &Map<String, Value>,
    references: &BTreeSet<String>,
) -> Result<()> {
    if let Some(rows) = object.get("sourceRefs") {
        validate_reference_rows(rows, references)?;
    }
    object
        .values()
        .try_for_each(|child| validate_citations(child, references))
}
