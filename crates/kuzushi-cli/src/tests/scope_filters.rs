use crate::{cli::Cli, command::Command};
use clap::Parser;

#[test]
fn scope_filter_flags_parse_recorded_ids_and_exact_records() {
    let record = "a".repeat(64);
    let cli = Cli::try_parse_from([
        "kuzushi",
        "findings",
        "--scope",
        "App,Other",
        "--scope-record",
        &record,
        "--json",
    ])
    .unwrap();
    let Some(Command::Findings {
        scope,
        scope_record,
        json,
        ..
    }) = cli.command
    else {
        panic!("expected findings command");
    };
    assert_eq!(scope, ["App", "Other"]);
    assert_eq!(scope_record, [record]);
    assert!(json);
}
