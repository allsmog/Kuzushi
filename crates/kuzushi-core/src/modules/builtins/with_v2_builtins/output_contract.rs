use crate::module_result::normalize_module_result;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

pub(super) fn normalize_tool_output_contract(name: &str, output: Value) -> Value {
    if is_catalog_metadata_tool(name) {
        return output;
    }
    normalize_module_result(output)
}

fn is_catalog_metadata_tool(name: &str) -> bool {
    matches!(name, "catalog:modules" | "catalog:tools")
}

#[cfg(test)]
fn normalize_output_value(output: Value) -> Value {
    normalize_module_result(output)
}

#[cfg(test)]
#[path = "output_contract_tests.rs"]
mod tests;
