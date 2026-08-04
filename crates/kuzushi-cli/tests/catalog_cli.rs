use serde_json::Value;
use std::process::{Command, Output};

fn kuzushi(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kuzushi"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn default_catalog_omits_labs_and_points_to_explicit_all_scope() {
    let modules = kuzushi(&["modules"]);
    assert!(modules.status.success());
    assert!(!stdout(&modules).contains("fuzz -"));
    let stderr = String::from_utf8(modules.stderr).unwrap();
    assert!(stderr.contains("Labs"), "{stderr}");
    assert!(stderr.contains("--all"), "{stderr}");

    let tools = kuzushi(&["tools"]);
    assert!(tools.status.success());
    assert!(!stdout(&tools).contains("fuzz:run"));
}

#[test]
fn all_scope_discloses_labs_in_plain_and_json_catalogs() {
    let plain_modules = kuzushi(&["modules", "--all"]);
    assert!(plain_modules.status.success());
    assert!(stdout(&plain_modules).contains("fuzz [labs]"));

    let plain_tools = kuzushi(&["tools", "--all"]);
    assert!(plain_tools.status.success());
    assert!(stdout(&plain_tools).contains("fuzz:run [labs]"));

    let json_modules = kuzushi(&["modules", "--all", "--json"]);
    assert!(json_modules.status.success());
    let rows: Value = serde_json::from_slice(&json_modules.stdout).unwrap();
    assert!(rows
        .as_array()
        .unwrap()
        .iter()
        .any(|row| { row["id"] == "fuzz" && row["maturity"] == "labs" }));

    let default_json = kuzushi(&["modules", "--json"]);
    assert!(default_json.status.success());
    let rows: Value = serde_json::from_slice(&default_json.stdout).unwrap();
    assert!(rows
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["maturity"] == "core"));
}
