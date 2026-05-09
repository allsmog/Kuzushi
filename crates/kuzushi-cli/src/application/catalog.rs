use anyhow::Result;
use kuzushi_core::ModuleRegistry;

pub(crate) fn modules_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &registry
                    .modules()
                    .map(|module| module.metadata())
                    .collect::<Vec<_>>()
            )?
        );
    } else {
        for module in registry.modules() {
            println!(
                "{} - {}",
                module.metadata().id,
                module.metadata().description
            );
        }
    }
    Ok(())
}

pub(crate) fn tools_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&registry.tools().collect::<Vec<_>>())?
        );
    } else {
        for tool in registry.tools() {
            println!("{} - {}", tool.name, tool.description);
        }
    }
    Ok(())
}
