//! Env-read boundary ratchet.
//!
//! Direct `std::env` reads belong at adapter/config/presentation
//! boundaries: secrets and credential tokens, `PATH`/`HOME`/XDG/git
//! process integration, spawn-environment sanitizers, provenance
//! fingerprints, config/env bootstrap, documented compatibility tool
//! locators, and test hooks. Domain types, module input parsers, scan
//! engines, and runtime policy code receive resolved values instead.
//!
//! This ratchet pins the audited set of files that read the environment,
//! so a new read in a new place is a deliberate, reviewed decision:
//! either pass a resolved value in from a boundary, or add the file here
//! with a category comment.

use std::path::{Path, PathBuf};

/// Audited 2026-07-21 (wave-3 B1). Relative to `src/`.
const AUDITED_ENV_READ_FILES: &[&str] = &[
    // Config / bootstrap boundaries.
    "agent_router/router_state.rs", // KUZUSHI_MODELS_FILE (operator models file)
    "config/apply_env_overrides.rs", // sanctioned env bootstrap tier
    "config/source_inventory.rs",   // reports which sanctioned env tier supplied a setting
    // PATH / HOME / process-integration lookups.
    "capabilities/fuzz_engine/engine_cli.rs", // PATH which (python3 for the engine)
    "capabilities/module_recommender/adapters.rs", // PATH probe for optional binaries
    "codeql_repository_execution/launcher.rs", // CodeQL launcher env/PATH/HOME adapter
    "modules/fuzz_module.rs",                 // HOME for the derived engine workspace
    "modules/pwn/mod.rs",                     // HOME for installed revng
    "process_lookup.rs",                      // PATH which
    "scan/engines/codeql/hex_value/codeql_binary.rs", // PATH which
    // Spawn-environment sanitizers (env_clear + selective re-add / scrub).
    "capabilities/uaf_hunt/adapters/clang_subprocess.rs", // PATH re-add + KUZUSHI_MCP_CLANG_BIN
    "modules/dynamic_loader.rs", // worker env sanitizer + KUZUSHI_DYNAMIC_MODULE_HOST
    "remediation/patch_process_adapter.rs", // PATH/CARGO_HOME/RUSTUP_HOME for validation env
    "scan/subprocess/try_wait.rs", // scanner env scrubber (allowlist filter)
    "verification/build_rust_trigger.rs", // generated sandbox harness reads its injected sink marker
    "worker_protocol.rs",                 // MCP/fuzz env sanitizers + credential tokens
    // Git integration mirrors git's own environment contract.
    "workspace/domain/workspace_state_initialization/git_policy/inputs.rs",
    "workspace/domain/workspace_state_initialization/proof_cache/path_snapshot.rs",
    // Documented compatibility tool locators / debug toggles.
    "capabilities/plugin_adapters/adapters/input.rs", // plugin-root env; tool input outranks
    "capabilities/taint_iris_next/application/codeql_dataflow.rs", // KUZUSHI_CODEQL_BIN
    "code_nav/ripgrep/ripgrep_binary.rs",             // KUZUSHI_RIPGREP_BIN
    "modules/builtins/with_v2_builtins/builtin_registration.rs", // adapter env presence probe
    "modules/plugin_resolution/mod.rs",               // plugin-root env; tool input outranks
    "semantic_cache/mod.rs", // KUZUSHI_SEMANTIC_CACHE kill switch (debug toggle)
    // Provenance / characterization.
    "run_artifacts/run_reproducibility_metadata.rs", // env fingerprint on run summaries
    "run_lifecycle/persistence/writer_characterization.rs", // ignored-test baseline input
    // Env reads confined to the file's inline test module.
    "scan/subprocess/scan_cancellation.rs", // owner-process re-exec test hook
    "test_env.rs", // shared cfg(test) ScopedEnv guard (reads to save/restore)
];

// Split so this file does not match its own detection pattern.
const ENV_READ_PATTERN: &str = concat!("env::", "var");

fn is_dedicated_test_file(relative: &str) -> bool {
    relative.ends_with("tests.rs") || relative.contains("/tests/")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn files_reading_env(src: &Path) -> Vec<String> {
    let mut sources = Vec::new();
    rust_sources(src, &mut sources);
    let mut found = Vec::new();
    for path in sources {
        let relative = path
            .strip_prefix(src)
            .expect("source under src/")
            .to_string_lossy()
            .replace('\\', "/");
        if is_dedicated_test_file(&relative) || relative == "env_boundary_lint.rs" {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        if body.contains(ENV_READ_PATTERN) {
            found.push(relative);
        }
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_reads_stay_within_the_audited_boundary_files() {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let found = files_reading_env(&src);

        let audited: std::collections::BTreeSet<&str> =
            AUDITED_ENV_READ_FILES.iter().copied().collect();
        let unaudited: Vec<&String> = found
            .iter()
            .filter(|file| !audited.contains(file.as_str()))
            .collect();
        assert!(
            unaudited.is_empty(),
            "new std::env read outside the audited boundary files: {unaudited:?}. \
             Pass a resolved value in from an adapter/config boundary, or audit \
             the read and add the file to AUDITED_ENV_READ_FILES with a category \
             comment."
        );

        let found: std::collections::BTreeSet<&str> = found.iter().map(String::as_str).collect();
        let stale: Vec<&&str> = AUDITED_ENV_READ_FILES
            .iter()
            .filter(|file| !found.contains(**file))
            .collect();
        assert!(
            stale.is_empty(),
            "AUDITED_ENV_READ_FILES has stale entries (file gone or no longer \
             reads the environment): {stale:?}. Remove them so the ratchet \
             stays honest."
        );
    }
}
