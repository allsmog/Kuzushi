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
    let destination = target.map_or_else(
        || "kuzushi: choose a target in the picker; run `demo` for the offline fixture".to_string(),
        |path| format!("kuzushi: target {}; opening operator shell", path.display()),
    );
    vec![
        "kuzushi: loading config and native registry...".to_string(),
        destination,
    ]
}
