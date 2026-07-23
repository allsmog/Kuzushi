//! Pure construction and decoding of agentic-fuzz-engine CLI invocations.
//!
//! Every engine verb is `python -m agentic_fuzz_engine.cli --data-root <dr>
//! <verb> ...` printing exactly one JSON payload on stdout with an
//! `ok`/`blockers` contract. Command execution stays in the module layer;
//! everything here is testable without a subprocess.

use super::FuzzPaths;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One fully-described engine call: program, argv, env, cwd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub envs: Vec<(String, String)>,
    pub cwd: PathBuf,
}

pub fn engine_invocation(paths: &FuzzPaths, verb_args: &[String]) -> EngineInvocation {
    let mut args = vec![
        "-m".to_string(),
        "agentic_fuzz_engine.cli".to_string(),
        "--data-root".to_string(),
        paths.data_root.display().to_string(),
    ];
    args.extend(verb_args.iter().cloned());
    EngineInvocation {
        program: paths.python_bin.clone(),
        args,
        envs: vec![
            (
                "PYTHONPATH".to_string(),
                paths.afe_repo.join("src").display().to_string(),
            ),
            (
                "AGENTIC_FUZZ_WORKSPACE".to_string(),
                paths.workspace_root.display().to_string(),
            ),
            // llvm-symbolizer hangs when the ambient environment exports a
            // debuginfod URL on egress-blocked hosts; keep symbolization local.
            ("DEBUGINFOD_URLS".to_string(), String::new()),
        ],
        cwd: paths.afe_repo.clone(),
    }
}

pub fn engine_command(invocation: &EngineInvocation) -> Command {
    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.args)
        .current_dir(&invocation.cwd)
        .stdin(std::process::Stdio::null());
    for (key, value) in &invocation.envs {
        command.env(key, value);
    }
    command
}

/// Decode the single JSON payload an engine verb prints. Tolerates non-JSON
/// prefix noise (stray warnings on stdout) by parsing from the first `{`.
pub fn parse_engine_json(stdout: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(stdout);
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(value);
    }
    let start = trimmed
        .find('{')
        .context("engine stdout carried no JSON payload")?;
    serde_json::Deserializer::from_str(&trimmed[start..])
        .into_iter::<Value>()
        .next()
        .context("engine stdout carried no decodable JSON payload")?
        .context("engine stdout JSON payload is malformed")
}

/// Engine verbs report `ok: false` plus `blockers` when refusing work
/// (disk headroom, missing toolchain). A payload without `ok` is success.
pub fn engine_ok(payload: &Value) -> bool {
    payload.get("ok").and_then(Value::as_bool).unwrap_or(true)
}

pub fn engine_blockers(payload: &Value) -> Vec<String> {
    payload
        .get("blockers")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Interpreter resolution mirrors the engine's own launcher: explicit
/// option, then the repo venv, then `python3` from PATH.
pub fn locate_python(afe_repo: &Path, explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return path.is_file().then(|| path.to_path_buf());
    }
    let venv = afe_repo.join(".venv/bin/python");
    if venv.is_file() {
        return Some(venv);
    }
    which_on_path("python3")
}

pub fn afe_repo_is_valid(dir: &Path) -> bool {
    dir.join("src/agentic_fuzz_engine/cli.py").is_file()
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_paths() -> FuzzPaths {
        FuzzPaths {
            afe_repo: PathBuf::from("/opt/afe"),
            python_bin: PathBuf::from("/opt/afe/.venv/bin/python"),
            workspace_root: PathBuf::from("/ws"),
            data_root: PathBuf::from("/ws/data"),
            source_dir: PathBuf::from("/repo"),
        }
    }

    #[test]
    fn invocation_carries_data_root_env_and_cwd() {
        let invocation = engine_invocation(
            &fixture_paths(),
            &["sink-scan".to_string(), "--source-root".to_string(), "/repo".to_string()],
        );

        assert_eq!(
            invocation.args,
            vec![
                "-m",
                "agentic_fuzz_engine.cli",
                "--data-root",
                "/ws/data",
                "sink-scan",
                "--source-root",
                "/repo"
            ]
        );
        assert_eq!(invocation.cwd, PathBuf::from("/opt/afe"));
        assert!(invocation
            .envs
            .contains(&("PYTHONPATH".to_string(), "/opt/afe/src".to_string())));
        assert!(invocation
            .envs
            .contains(&("AGENTIC_FUZZ_WORKSPACE".to_string(), "/ws".to_string())));
        assert!(invocation
            .envs
            .contains(&("DEBUGINFOD_URLS".to_string(), String::new())));
    }

    #[test]
    fn engine_json_parses_clean_ok_blockers_and_prefixed_output() {
        let clean = parse_engine_json(br#"{"ok": true, "rounds_completed": 2}"#).unwrap();
        assert!(engine_ok(&clean));
        assert!(engine_blockers(&clean).is_empty());

        let refused =
            parse_engine_json(br#"{"ok": false, "blockers": ["disk headroom below 10 GB"]}"#)
                .unwrap();
        assert!(!engine_ok(&refused));
        assert_eq!(refused["blockers"][0], "disk headroom below 10 GB");

        let noisy = parse_engine_json(b"warning: locale\n{\"ok\": true}\n").unwrap();
        assert_eq!(noisy, json!({"ok": true}));

        assert!(parse_engine_json(b"no json here").is_err());
    }

    #[test]
    fn python_resolution_prefers_explicit_then_venv() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        std::fs::create_dir_all(repo.join(".venv/bin")).unwrap();
        std::fs::write(repo.join(".venv/bin/python"), "").unwrap();
        let explicit = repo.join("custom-python");
        std::fs::write(&explicit, "").unwrap();

        assert_eq!(
            locate_python(repo, Some(&explicit)),
            Some(explicit.clone())
        );
        assert_eq!(
            locate_python(repo, Some(&repo.join("missing"))),
            None,
            "an explicit interpreter that does not exist must not fall back"
        );
        assert_eq!(locate_python(repo, None), Some(repo.join(".venv/bin/python")));
    }

    #[test]
    fn afe_repo_validity_requires_the_cli_module() {
        let temp = tempfile::tempdir().unwrap();
        assert!(!afe_repo_is_valid(temp.path()));
        std::fs::create_dir_all(temp.path().join("src/agentic_fuzz_engine")).unwrap();
        std::fs::write(temp.path().join("src/agentic_fuzz_engine/cli.py"), "").unwrap();
        assert!(afe_repo_is_valid(temp.path()));
    }
}
