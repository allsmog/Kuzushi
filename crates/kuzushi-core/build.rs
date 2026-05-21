use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=KUZUSHI_GIT_SHA");
    println!("cargo:rerun-if-env-changed=KUZUSHI_GIT_BRANCH");
    emit_build_env("KUZUSHI_GIT_SHA", &["rev-parse", "--short=12", "HEAD"]);
    emit_build_env("KUZUSHI_GIT_BRANCH", &["rev-parse", "--abbrev-ref", "HEAD"]);
}

fn emit_build_env(name: &str, git_args: &[&str]) {
    if let Some(value) = env_value(name).or_else(|| git_output(git_args)) {
        println!("cargo:rustc-env={name}={value}");
    }
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(non_empty)
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    non_empty(String::from_utf8_lossy(&output.stdout).to_string())
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}
