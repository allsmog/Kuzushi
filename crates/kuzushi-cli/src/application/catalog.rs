use anyhow::Result;
use kuzushi_core::modules::{BuiltinModule, ModuleMaturity, ModuleMetadata, ToolDescriptor};
use kuzushi_core::ModuleRegistry;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleCatalogRow<'a> {
    #[serde(flatten)]
    metadata: &'a ModuleMetadata,
    maturity: ModuleMaturity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolCatalogRow<'a> {
    module_id: &'a str,
    maturity: ModuleMaturity,
    #[serde(flatten)]
    tool: &'a ToolDescriptor,
}

pub(crate) fn modules_command(json: bool, all: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    let modules = selected_modules(&registry, all);
    if json {
        let rows = modules
            .iter()
            .map(|module| ModuleCatalogRow {
                metadata: module.metadata(),
                maturity: module.maturity(),
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        for module in modules {
            print_module(module, all);
        }
        if !all {
            append_non_core_summary(&registry);
        }
    }
    Ok(())
}

pub(crate) fn tools_command(json: bool, all: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    let tools = selected_tools(&registry, all);
    if json {
        let rows = tools
            .iter()
            .map(|(module, tool)| ToolCatalogRow {
                module_id: &module.metadata().id,
                maturity: module.maturity(),
                tool,
            })
            .collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        for (module, tool) in tools {
            print_tool(module, tool, all);
        }
        if !all {
            append_non_core_summary(&registry);
        }
    }
    Ok(())
}

fn selected_modules(registry: &ModuleRegistry, all: bool) -> Vec<&BuiltinModule> {
    if all {
        registry.modules().collect()
    } else {
        registry.discoverable_modules().collect()
    }
}

fn selected_tools(registry: &ModuleRegistry, all: bool) -> Vec<(&BuiltinModule, &ToolDescriptor)> {
    if all {
        registry.catalog_tools_with_modules().collect()
    } else {
        registry.discoverable_catalog_tools_with_modules().collect()
    }
}

fn print_module(module: &BuiltinModule, show_maturity: bool) {
    let metadata = module.metadata();
    if show_maturity {
        println!(
            "{} [{}] - {}",
            metadata.id,
            module.maturity().as_str(),
            metadata.description
        );
    } else {
        println!("{} - {}", metadata.id, metadata.description);
    }
}

fn print_tool(module: &BuiltinModule, tool: &ToolDescriptor, show_maturity: bool) {
    if show_maturity {
        println!(
            "{} [{}] - {}",
            tool.name,
            module.maturity().as_str(),
            tool.description
        );
    } else {
        println!("{} - {}", tool.name, tool.description);
    }
}

fn append_non_core_summary(registry: &ModuleRegistry) {
    let labs = registry
        .modules()
        .filter(|module| module.maturity() == ModuleMaturity::Labs)
        .count();
    let compatibility = registry
        .modules()
        .filter(|module| module.maturity() == ModuleMaturity::Compatibility)
        .count();
    if labs + compatibility > 0 {
        eprintln!(
            "catalog: {labs} Labs and {compatibility} Compatibility module(s) omitted from the default list; use --all to inspect maturity labels and exact tool ids"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_catalog_discloses_labs_without_promoting_them() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
        let fuzz = registry
            .modules()
            .find(|module| module.metadata().id == "fuzz")
            .expect("fuzz module must remain explicitly catalogued");

        assert_eq!(fuzz.maturity(), ModuleMaturity::Labs);
        assert!(registry
            .discoverable_modules()
            .all(|module| module.metadata().id != "fuzz"));
        assert!(registry.resolve_tool("fuzz:run").is_some());
    }

    #[test]
    fn all_is_an_explicit_scope_shared_by_plain_and_json_rendering() {
        let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();

        assert!(selected_modules(&registry, false)
            .iter()
            .all(|module| module.maturity().is_core()));
        assert!(selected_modules(&registry, true)
            .iter()
            .any(|module| module.maturity() == ModuleMaturity::Labs));
        assert!(selected_tools(&registry, false)
            .iter()
            .all(|(module, _)| module.maturity().is_core()));
        assert!(selected_tools(&registry, true)
            .iter()
            .any(|(module, _)| module.maturity() == ModuleMaturity::Labs));
    }
}
