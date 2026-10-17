use super::*;

pub(crate) fn parse_triggers(raw: &Value) -> Vec<SystemsTriggerHypothesis> {
    let Some(items) = raw.get("triggers").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let id = string_field(object.get("id"));
            let surface_id = string_field(object.get("surfaceId"));
            let ordered_steps = string_array(object.get("orderedSteps"));
            let expected_primitive = string_field(object.get("expectedPrimitive"));
            let rationale = string_field(object.get("rationale"));
            if id.is_empty()
                || surface_id.is_empty()
                || ordered_steps.is_empty()
                || expected_primitive.is_empty()
                || rationale.is_empty()
            {
                return None;
            }
            Some(SystemsTriggerHypothesis {
                id,
                surface_id,
                ordered_steps,
                boundary_assignments: string_record(object.get("boundaryAssignments")),
                state_preconditions: string_array(object.get("statePreconditions")),
                attacker_controlled_fields: string_array(object.get("attackerControlledFields")),
                expected_primitive,
                cheap_verifiable: object
                    .get("cheapVerifiable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                rationale,
            })
        })
        .collect()
}

pub(crate) fn context_from_input(input: &Value) -> Option<Result<SystemsContextOutput>> {
    let value = input
        .get("systemsContext")
        .or_else(|| input.get("systems_context"))
        .or_else(|| input.get("context"))?;
    Some(serde_json::from_value(value.clone()).context("invalid systems context input"))
}
