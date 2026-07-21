use anyhow::Result;
use kuzushi_core::{ConfigDiagnostic, V2Config};
use std::path::Path;

/// Load effective config at a CLI presentation boundary. Diagnostics go to
/// stderr so JSON stdout remains machine-readable.
pub(crate) fn load_cli_config(target: Option<&Path>) -> Result<V2Config> {
    let loaded = load_cli_config_with_diagnostics(target)?;
    emit_config_diagnostics(&loaded.diagnostics);
    Ok(loaded.config)
}

pub(crate) fn load_cli_config_with_diagnostics(
    target: Option<&Path>,
) -> Result<kuzushi_core::LoadedConfig> {
    kuzushi_core::load_config_for_target_with_diagnostics(target)
}

pub(crate) fn emit_config_diagnostics(diagnostics: &[ConfigDiagnostic]) {
    for diagnostic in diagnostics {
        eprintln!("{diagnostic}");
    }
}

pub(crate) fn emit_runtime_diagnostics() {
    for diagnostic in kuzushi_core::take_runtime_diagnostics() {
        eprintln!("[{}] {}", diagnostic.source, diagnostic.message);
    }
}

pub(crate) fn exit_after_runtime_diagnostics(code: i32) -> ! {
    emit_runtime_diagnostics();
    std::process::exit(code)
}
