use super::*;

fn command() -> Command {
    let mut command = Command::new("semgrep");
    command.args(["--json", "--"]);
    command
}

#[test]
fn short_literal_members_pack_up_to_the_file_ceiling_without_reordering() {
    let files = (0..1025).map(|n| format!("f{n}.py")).collect::<Vec<_>>();
    let batches = FileBatches::new(&command(), &files)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        batches.iter().map(|batch| batch.len()).collect::<Vec<_>>(),
        vec![1024, 1]
    );
    assert_eq!(batches.concat(), files);
}

#[test]
fn encoded_bytes_bound_long_unicode_paths_without_splitting_or_changing_them() {
    let files = (0..40)
        .map(|n| format!("{} [route {n}].py", "目录/😀".repeat(30)))
        .collect::<Vec<_>>();
    let command = command();
    let fixed = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|s| s.as_encoded_bytes().len() + 1)
        .sum::<usize>();
    let batches = FileBatches::new(&command, &files)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert!(batches.len() > 1);
    for batch in &batches {
        assert!(fixed + batch.iter().map(|s| s.len() + 1).sum::<usize>() <= MAX_ARGUMENT_BYTES);
    }
    assert_eq!(batches.concat(), files);
}

#[test]
fn fixed_arguments_consume_the_same_allowance_as_file_arguments() {
    let mut command = Command::new("s");
    command.arg("x".repeat(MAX_ARGUMENT_BYTES - 8));
    let files = vec!["aaa".into(), "b".into()];
    let batches = FileBatches::new(&command, &files)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        batches.iter().map(|batch| batch.len()).collect::<Vec<_>>(),
        vec![1, 1]
    );
}

#[test]
fn oversized_fixed_arguments_fail_before_any_process_or_source_expansion() {
    let mut command = command();
    command.arg("x".repeat(MAX_ARGUMENT_BYTES));
    assert!(FileBatches::new(&command, &["selected.py".into()]).is_err());
}

#[test]
fn an_unrepresentable_member_ends_iteration_honestly_after_prior_batches() {
    let files = vec![
        "a.py".into(),
        "x".repeat(MAX_ARGUMENT_BYTES),
        "unstarted.py".into(),
    ];
    let mut batches = FileBatches::new(&command(), &files).unwrap();
    assert_eq!(batches.next().unwrap().unwrap(), &files[..1]);
    assert!(batches.next().unwrap().is_err());
    assert!(batches.next().is_none());
}

#[test]
fn no_files_create_no_batches() {
    assert!(FileBatches::new(&command(), &[]).unwrap().next().is_none());
}
