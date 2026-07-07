use super::*;
use std::path::{Path, PathBuf};

pub(super) fn langgraph_bridge_preflight_error(
    config: &V2Config,
    tool_name: &str,
) -> Option<String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let command = config
        .runtime
        .langgraph_bridge_command
        .clone()
        .unwrap_or_else(|| kuzushi_openai::default_langgraph_bridge_command(&cwd));
    if command.is_empty() {
        return Some(format!(
            "{tool_name} requires LangGraph, but runtime.langgraph_bridge_command is empty"
        ));
    }
    if !command_executable_available(&command[0], &cwd) {
        return Some(format!(
            "{tool_name} requires LangGraph, but Node/bridge executable `{}` was not found. Install Node.js or set runtime.langgraph_bridge_command; bundled bridge script is scripts/langgraph-bridge.mjs.",
            command[0]
        ));
    }
    missing_bundled_bridge_script(&command, &cwd).map(|script| {
        format!(
            "{tool_name} requires LangGraph, but bridge script `{}` was not found. Run from the Kuzushi repo, install the packaged bridge, or set runtime.langgraph_bridge_command; Node executable is `{}`.",
            script.display(),
            command[0]
        )
    })
}

fn command_executable_available(command: &str, cwd: &Path) -> bool {
    let path_like = command.contains('/') || command.contains('\\');
    if path_like {
        return command_path(command, cwd).is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(command);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

fn missing_bundled_bridge_script(command: &[String], cwd: &Path) -> Option<PathBuf> {
    let script = command.get(1)?;
    if !script.ends_with("langgraph-bridge.mjs") {
        return None;
    }
    let path = command_path(script, cwd);
    (!path.is_file()).then_some(path)
}

fn command_path(command: &str, cwd: &Path) -> PathBuf {
    let path = PathBuf::from(command);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_preflight_accepts_path_like_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let bridge = tmp.path().join("bridge.sh");
        std::fs::write(&bridge, "#!/bin/sh\n").unwrap();
        assert!(command_executable_available(
            bridge.to_str().unwrap(),
            tmp.path()
        ));
    }

    #[test]
    fn bridge_preflight_reports_missing_bundled_script() {
        let tmp = tempfile::tempdir().unwrap();
        let command = vec![
            "node".to_string(),
            "scripts/langgraph-bridge.mjs".to_string(),
        ];
        let missing = missing_bundled_bridge_script(&command, tmp.path()).unwrap();
        assert_eq!(missing, tmp.path().join("scripts/langgraph-bridge.mjs"));
    }
}
