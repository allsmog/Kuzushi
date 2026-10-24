//! Audit metadata consistency is separate from functional qualification.
use crate::modules::{BuiltinModule, ModuleRegistry, ToolDescriptor};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn visible_matrix() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/assessments/bounded-investigation-tools.json"
    )))
    .unwrap()
}

fn internal_matrix() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/assessments/internal-investigation-tools.json"
    )))
    .unwrap()
}

fn indexed_rows(matrix: &Value, key: &str) -> BTreeMap<String, Value> {
    let rows = matrix["tools"].as_array().unwrap();
    let indexed = rows
        .iter()
        .map(|row| (row[key].as_str().unwrap().to_owned(), row.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        rows.len(),
        indexed.len(),
        "audit matrix has duplicate tool identities"
    );
    indexed
}

fn visible_facts(module: &BuiltinModule, tool: &ToolDescriptor) -> Value {
    json!({
        "module": module.metadata().id,
        "declaredMaturity": tool.effective_maturity(module.maturity()),
        "declaredModuleMaturity": module.maturity(),
        "discoveryMaturityOverride": tool.discovery_maturity,
        "declaredPhase": tool.phase,
        "runtimeRequirement": tool.runtime_requirement,
        "headlessDeclared": tool.headless,
        "workspaceRequirement": tool.workspace_requirement,
        "findingStoreRequirement": tool.finding_store_requirement,
        "phaseResultDeclared": tool.phase_result,
        "declaredOptions": tool.options.iter().map(|option|&option.name).collect::<Vec<_>>(),
        "requiredOptions": tool.options.iter().filter(|option|option.required).map(|option|&option.name).collect::<Vec<_>>(),
        "descriptorSha256": crate::worker_protocol::sha256_digest(&crate::review_yield::domain::canonical_json_bytes(tool).unwrap()).0,
    })
}

fn field_differences(name: &str, row: &Value, facts: &Value) -> Vec<String> {
    facts
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, value)| row[*key] != **value)
        .map(|(key, value)| format!("{name}: {key}: matrix={} registry={value}", row[key]))
        .collect()
}

#[test]
fn visible_audit_facts_match_the_current_registry_without_qualifying_execution() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let rows = indexed_rows(&visible_matrix(), "tool");
    let actual = registry
        .catalog_tools_with_modules()
        .map(|(module, tool)| (tool.name.clone(), visible_facts(module, tool)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        rows.keys().collect::<Vec<_>>(),
        actual.keys().collect::<Vec<_>>(),
        "visible audit membership changed"
    );
    let differences = actual
        .iter()
        .flat_map(|(name, facts)| field_differences(name, &rows[name], facts))
        .collect::<Vec<_>>();
    assert!(
        differences.is_empty(),
        "Review audit metadata without inventing functional evidence:\n{}",
        differences.join("\n")
    );
}

fn internal_facts(module: &BuiltinModule, tool: &ToolDescriptor) -> Value {
    json!({
        "module": module.metadata().id, "moduleHidden": module.is_hidden(),
        "moduleMaturity": module.maturity(), "toolHidden": tool.hidden,
        "effectiveMaturity": tool.effective_maturity(module.maturity()),
        "dagNode": module.dag_nodes().iter().any(|node| node.id == tool.name),
        "phase": tool.phase, "phaseResult": tool.phase_result,
        "runtime": tool.runtime_requirement, "effect": tool.effect, "approval": tool.approval,
        "workspace": tool.workspace_requirement, "findingStore": tool.finding_store_requirement,
        "allowanceCategory": tool.allowance_category,
        "optionNames": tool.options.iter().map(|option|&option.name).collect::<Vec<_>>(),
    })
}

#[test]
fn visible_and_internal_audits_partition_every_registered_action() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let visible = indexed_rows(&visible_matrix(), "tool");
    let internal = indexed_rows(&internal_matrix(), "name");
    let names = visible
        .keys()
        .chain(internal.keys())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names.len(),
        visible.len() + internal.len(),
        "audit identities overlap"
    );
    assert_eq!(
        names,
        registry.tools.keys().collect::<BTreeSet<_>>(),
        "registered actions missing from the audit"
    );
    let mut differences = Vec::new();
    let mut checked = BTreeSet::new();
    for module in registry.all_modules() {
        for tool in module.tools() {
            if let Some(row) = internal.get(&tool.name) {
                checked.insert(tool.name.clone());
                differences.extend(field_differences(
                    &tool.name,
                    row,
                    &internal_facts(module, tool),
                ));
            }
        }
    }
    assert_eq!(
        checked,
        internal.keys().cloned().collect(),
        "internal metadata rows were skipped"
    );
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn in_scope_visible_actions_keep_all_required_audit_dimensions_explicit() {
    let matrix = visible_matrix();
    let excluded = matrix["currentRegistryCensus"]["excludedVisibleTools"]
        .as_array()
        .unwrap();
    let dimensions = [
        "purposeAndValue",
        "phaseAgreement",
        "requiredInputs",
        "sharedDispatchExecution",
        "artifactConsumption",
        "failureAndRecovery",
        "approvedResources",
        "scopeEnforcement",
        "interfaceParity",
    ];
    for row in matrix["tools"].as_array().unwrap() {
        if excluded.contains(&row["tool"]) {
            continue;
        }
        for dimension in dimensions {
            assert!(
                row["auditDimensions"][dimension]
                    .as_str()
                    .is_some_and(|text| !text.trim().is_empty()),
                "{}: missing {dimension}; pending evidence must stay explicit",
                row["tool"]
            );
        }
        assert_ne!(row["readinessVerdict"], "not-assigned", "{}", row["tool"]);
    }
}
