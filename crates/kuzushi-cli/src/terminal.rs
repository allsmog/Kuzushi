use std::io::{self, IsTerminal};
use std::path::Path;

pub(crate) fn plain_output_requested(flag: bool) -> bool {
    flag || std::env::var_os("KUZUSHI_PLAIN").is_some()
        || std::env::var_os("KUZUSHI_SCREEN_READER").is_some()
        || std::env::var_os("KUZUSHI_LOW_BANDWIDTH").is_some()
}

pub(crate) fn should_emit_shell_startup_progress(plain: bool) -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal() && !plain
}

pub(crate) fn shell_startup_progress_messages(target: Option<&Path>) -> Vec<String> {
    let target_label = target
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let scan_command = if target.is_some() { "scan" } else { "scan ." };
    vec![
        "kuzushi: loading config and native registry...".to_string(),
        format!("kuzushi: target {target_label}; first finding: {scan_command}, then findings"),
    ]
}
