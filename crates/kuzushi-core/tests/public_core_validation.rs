#![cfg(not(feature = "private-cpg"))]

use kuzushi_core::{
    cpg_artifact_langs, cpg_engine_available, cpg_engine_unavailable_message, cpg_has_artifacts,
    cpg_supported_languages,
};

#[test]
fn credential_free_core_discloses_private_engine_absence() {
    let target = tempfile::tempdir().unwrap();
    let artifact_dir = target.path().join(".kuzushi/cpg-rs");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("rust.v0.cpg"), b"CPG1").unwrap();

    assert!(!cpg_engine_available());
    assert!(cpg_supported_languages().is_empty());
    assert!(!cpg_has_artifacts(target.path()));
    assert!(cpg_artifact_langs(target.path()).is_empty());
    assert!(cpg_engine_unavailable_message().contains("not compiled"));
}
