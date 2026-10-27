use super::*;

fn balanced(files: &[String]) -> Value {
    sample(files, Some(&json!(BALANCED))).unwrap()
}

#[test]
fn late_root_and_directory_examples_are_preserved_inside_existing_bounds() {
    let mut files: Vec<_> = (0..600)
        .map(|n| format!("a/component/unit_{n:03}.py"))
        .collect();
    files.extend(["z/component/worker.py".into(), "workspace.json".into()]);
    let selection = balanced(&files);
    let names = selection["items"].as_array().unwrap();
    assert!(names.contains(&json!("workspace.json")));
    assert!(names.contains(&json!("z/component/worker.py")));
    assert_eq!(names.len(), MAX_NAMES);
    assert!(serde_json::to_vec(names).unwrap().len() <= MAX_BYTES);
    assert_eq!(selection["omitted"], files.len() - names.len());
    assert_eq!(selection["rootFiles"], json!({"supplied":1,"total":1}));
    assert_eq!(
        selection["directoryGroups"],
        json!({"supplied":2,"total":2})
    );
    assert_eq!(
        names
            .iter()
            .map(|path| path.as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        names.len()
    );
}

#[test]
fn omitted_and_explicit_legacy_selection_preserve_the_original_sample_bytes() {
    let files: Vec<_> = (0..600).map(|n| format!("group/file_{n:03}.py")).collect();
    let original = super::super::sample(&files, MAX_NAMES, MAX_BYTES).unwrap();
    for selection in [None, Some(json!("prefix-v1"))] {
        let current = sample(&files, selection.as_ref()).unwrap();
        assert_eq!(
            serde_json::to_vec(&current).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
        assert!(summary(&current).is_none());
    }
}

#[test]
fn excess_root_names_disclose_that_directory_examples_did_not_fit() {
    let mut files: Vec<_> = (0..520).map(|n| format!("root_{n:04}.md")).collect();
    files.push("service/app/main.py".into());
    let selection = balanced(&files);
    assert_eq!(selection["rootFiles"], json!({"supplied":512,"total":520}));
    assert_eq!(
        selection["directoryGroups"],
        json!({"supplied":0,"total":1})
    );
    assert!(summary(&selection)
        .unwrap()
        .contains("root names 512/520, directory groups 0/1"));
}

#[test]
fn oversized_names_do_not_hide_a_later_fitting_example() {
    let mut files: Vec<_> = (0..513)
        .map(|n| format!("a{n:04}{}", "é".repeat(MAX_BYTES)))
        .collect();
    files.push("z.py".into());
    let selection = balanced(&files);
    assert_eq!(selection["items"], json!(["z.py"]));
    assert_eq!(selection["omitted"], 513);
}

#[test]
fn balancing_is_stable_and_does_not_treat_literal_backslashes_as_separators() {
    let mut files = vec![
        "client\\scope/file.py".into(),
        "client/scope/file.py".into(),
        "workspace.json".into(),
        "client\\scope.py".into(),
    ];
    let first = balanced(&files);
    files.reverse();
    assert_eq!(balanced(&files), first);
    assert_eq!(group("client\\scope.py"), "");
    assert_eq!(group("client\\scope/file.py"), "client\\scope");
    assert_eq!(group("client/scope/file.py"), "client/scope");
    assert_eq!(first["rootFiles"]["total"], 2);
    assert_eq!(first["directoryGroups"]["total"], 2);
}

#[test]
fn empty_membership_and_invalid_selection_are_honest() {
    assert_eq!(balanced(&[])["items"], json!([]));
    for invalid in [Value::Null, json!(false), json!(""), json!("automatic")] {
        assert!(sample(&[], Some(&invalid)).is_err());
    }
}

#[test]
fn the_inventory_entry_limit_still_produces_one_bounded_filename_sample() {
    let files: Vec<_> = (0..100_000)
        .map(|n| format!("component_{n:05}/src/file.rs"))
        .collect();
    let selection = balanced(&files);
    let supplied = selection["items"].as_array().unwrap();
    assert!(supplied.len() <= MAX_NAMES);
    assert!(serde_json::to_vec(supplied).unwrap().len() <= MAX_BYTES);
    assert_eq!(selection["total"], 100_000);
    assert_eq!(selection["omitted"], 100_000 - supplied.len());
    assert_eq!(selection["directoryGroups"]["total"], 100_000);
    assert_eq!(selection["directoryGroups"]["supplied"], supplied.len());
}
