use super::*;
use crate::workspace::application::{
    export_investigation_receipt::{attach_bundle_receipt, write_receipt},
    export_markdown_bundle::write_markdown_bundle,
    export_projection_model::WorkspaceFindingExportRecord,
    investigation_report::{tests::planned_report, InvestigationReportDocument},
};
use crate::workspace::{
    export_workspace_findings_with_options, WorkspaceExportFormat, WorkspaceExportOptions,
};
use crate::WorkspaceTarget;

fn assert_no_staging_directories(parent: &Path) {
    assert!(fs::read_dir(parent).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".kuzushi-report-")));
}

#[test]
fn incomplete_build_leaves_the_destination_absent_and_retryable() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let output = root.path().join("report");
    let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle));
    let missing = WorkspaceFindingExportRecord {
        alias: "F_fixture".into(),
        fingerprint: "missing-source".into(),
        ..Default::default()
    };
    let error = publish_bundle(&output, |staging| {
        let result = write_markdown_bundle(&workspace, &[], &[missing], staging, &options, 1);
        assert!(staging.join("README.md").exists());
        result
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("missing finding source"));
    assert!(!output.exists());
    assert_no_staging_directories(root.path());
    publish_bundle(&output, |staging| {
        assert!(!output.exists());
        write_markdown_bundle(&workspace, &[], &[], staging, &options, 0)
    })
    .unwrap();
    assert!(output.join("manifest.json").is_file());
    assert_no_staging_directories(root.path());
}

#[test]
fn receipt_write_failure_discards_the_unpublished_bundle_and_allows_same_path_retry() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let receipt = InvestigationReportDocument::Study(planned_report(root.path()));
    let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle))
        .with_campaign(Some("report-study".into()));
    let output = root.path().join("report");
    fs::create_dir(&output).unwrap();
    let result = publish_bundle(&output, |staging| {
        write_markdown_bundle(&workspace, &[], &[], staging, &options, 0)?;
        let path = staging.join("investigation.json");
        let _fault = crate::fs_atomic::inject_atomic_write_fault(
            path.clone(),
            crate::fs_atomic::AtomicWriteFaultPoint::AfterTempSync,
        );
        write_receipt(&path, &receipt)?;
        attach_bundle_receipt(staging, &receipt)
    });
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    assert_no_staging_directories(root.path());
    let exported = export_workspace_findings_with_options(&workspace, &output, &options).unwrap();
    assert_eq!(
        exported.investigation_receipt_path,
        Some(output.join("investigation.json").canonicalize().unwrap())
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["metadata"]["investigation"]["occurrence"]["pending"],
        3
    );
    assert_eq!(
        manifest["metadata"]["investigation"]["allowance"],
        serde_json::Value::Null
    );
    assert_no_staging_directories(root.path());
}

#[test]
fn a_failed_build_preserves_an_existing_empty_destination() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("report");
    fs::create_dir(&output).unwrap();
    assert!(publish_bundle(&output, |staging| {
        fs::write(staging.join("README.md"), "incomplete")?;
        anyhow::bail!("owned export fault")
    })
    .is_err());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    assert_no_staging_directories(root.path());
}

#[test]
fn a_destination_filled_during_build_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("report");
    assert!(publish_bundle(&output, |staging| {
        fs::write(staging.join("README.md"), "new report")?;
        fs::create_dir(&output)?;
        fs::write(output.join("operator.txt"), "retained work")?;
        Ok(())
    })
    .is_err());
    assert_eq!(
        fs::read_to_string(output.join("operator.txt")).unwrap(),
        "retained work"
    );
    assert!(!output.join("README.md").exists());
    assert_no_staging_directories(root.path());
}

#[test]
fn failed_install_restores_the_empty_directory_without_overwriting_any_file() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("report");
    fs::create_dir(&output).unwrap();
    assert!(install_bundle(&root.path().join("missing-stage"), &output).is_err());
    assert_eq!(fs::read_dir(output).unwrap().count(), 0);
}

#[test]
fn existing_files_are_rejected_before_any_build() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("operator.txt");
    fs::write(&output, "retained work").unwrap();
    assert!(publish_bundle(&output, |_| panic!("must not build over a file")).is_err());
    assert_eq!(fs::read_to_string(output).unwrap(), "retained work");
    assert_no_staging_directories(root.path());
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_rejected_without_changing_the_link_or_target() {
    let root = tempfile::tempdir().unwrap();
    let actual = root.path().join("actual");
    let output = root.path().join("linked");
    fs::create_dir(&actual).unwrap();
    std::os::unix::fs::symlink(&actual, &output).unwrap();
    assert!(publish_bundle(&output, |_| panic!("must not follow a symbolic link")).is_err());
    assert!(fs::symlink_metadata(output)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_dir(actual).unwrap().count(), 0);
}

#[test]
fn concurrent_exports_publish_one_complete_generation_without_overwriting_it() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("report");
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let handles = (0..2)
            .map(|index| {
                let output = &output;
                let barrier = &barrier;
                scope.spawn(move || {
                    publish_bundle(output, |staging| {
                        fs::write(staging.join("README.md"), index.to_string())?;
                        fs::write(staging.join("manifest.json"), index.to_string())?;
                        barrier.wait();
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        fs::read(output.join("README.md")).unwrap(),
        fs::read(output.join("manifest.json")).unwrap()
    );
    assert_no_staging_directories(root.path());
}
