use super::*;

#[test]
fn lesson_runs_cannot_enter_automatic_artifact_context() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    for (index, tool) in [
        "findings:lesson-save",
        "findings:lesson-generate",
        "findings:lesson-review",
        "findings:lessons",
        "threat-model:reuse-lessons",
    ]
    .iter()
    .enumerate()
    {
        let dir = crate::run_artifacts::run_dir(root.path(), &format!("lesson-{index}"));
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(
            dir.join("run.json"),
            serde_json::to_string(&json!({"tool":tool})).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested/result.json"),
            r#"{"draft":"unique lesson marker"}"#,
        )
        .unwrap();
        let source = relative_workspace_path(root.path(), &dir.join("nested/result.json"));
        assert!(workspace_artifact_record(&workspace, source)
            .unwrap()
            .is_none());
    }
    assert!(artifact_record_candidates(&workspace)
        .unwrap()
        .iter()
        .all(|path| !path.contains("/runs/lesson-")));
    index_workspace_artifacts(&workspace).unwrap();
    let result = search_artifact_knowledge(&workspace, "unique lesson marker", 10).unwrap();
    assert!(result.results.is_empty());
}

#[test]
fn report_exports_cannot_supply_lessons_through_automatic_artifact_search() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let reports = root.path().join(".kuzushi/reports");
    fs::create_dir_all(&reports).unwrap();
    for (leaf, body) in [
        (
            "../custom-lessons.json",
            r#"{"lessons":[{"lessonRef":{},"lesson":{"content":{"text":"unique lesson marker"}}}]}"#,
        ),
        (
            "findings.json",
            r#"{"lessons":[{"lessonRef":{},"lesson":{"content":{"text":"unique lesson marker"}}}]}"#,
        ),
        (
            "report.sarif",
            r#"{"kuzushiLessons":[{"content":{"text":"unique lesson marker"}}]}"#,
        ),
        (
            "report.md",
            "## Reusable lessons\n\n    {\"lessonRef\":{},\"text\":\"unique lesson marker\"}",
        ),
    ] {
        let path = reports.join(leaf);
        fs::write(&path, body).unwrap();
        let path = path.canonicalize().unwrap();
        assert!(workspace_artifact_record(
            &workspace,
            relative_workspace_path(&root.path().canonicalize().unwrap(), &path)
        )
        .unwrap()
        .is_none());
    }
}

#[test]
fn active_mirror_lessons_are_not_reused_through_unselected_artifact_search() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let path = crate::capabilities::persistent_threat_model_path(root.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path,r#"{"systemContext":"Normal source context","reviewedLessons":[{"content":{"text":"unique lesson marker"}}]}"#).unwrap();
    let record = workspace_artifact_record(&workspace, relative_workspace_path(root.path(), &path))
        .unwrap()
        .unwrap();
    assert!(record.body.contains("Normal source context"));
    assert!(!record.body.contains("unique lesson marker"));
}

#[test]
fn exact_context_reads_and_prompt_digests_cannot_leak_selected_lessons_through_run_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let dir = crate::run_artifacts::run_dir(root.path(), "context-read");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("run.json"), r#"{"tool":"threat-model:read"}"#).unwrap();
    for (leaf, body) in [
        (
            "result.json",
            r#"{"data":{"document":{"reviewedLessons":[{"content":{"text":"unique lesson marker"}}]}}}"#,
        ),
        (
            "prompt.txt",
            "Operator-reviewed lessons for this context: unique lesson marker",
        ),
    ] {
        fs::write(dir.join(leaf), body).unwrap();
        assert!(workspace_artifact_record(
            &workspace,
            relative_workspace_path(root.path(), &dir.join(leaf))
        )
        .unwrap()
        .is_none());
    }
}
