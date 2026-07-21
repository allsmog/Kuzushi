use super::*;
use kuzushi_core::{V2Config, WorkspaceTarget};
use std::path::PathBuf;

pub(super) struct PhaseReferenceFixture {
    _target: tempfile::TempDir,
    target_root: PathBuf,
    canonical_target_root: PathBuf,
    target_name: String,
    pub(super) app: ShellApp,
}

impl PhaseReferenceFixture {
    pub(super) fn new(page: WorkbenchPage, width: u16, height: u16) -> Self {
        let target = tempfile::tempdir().expect("phase reference target");
        let mut app = reference_app(target.path(), page, width, height);
        crate::app::seed_pdf_phase_reference_fixture(
            &mut app,
            target.path(),
            crate::app::PhaseFixtureLifecycle::Live,
        )
        .expect("phase reference fixture");
        hydrate_fix_truth(&mut app, target.path(), page);
        app.set_running_tool_for_test("context:build");
        let target_root = target.path().to_path_buf();
        let canonical_target_root = target_root
            .canonicalize()
            .unwrap_or_else(|_| target_root.clone());
        let target_name = target_name(&target_root);
        Self {
            _target: target,
            target_root,
            canonical_target_root,
            target_name,
            app,
        }
    }

    pub(super) fn normalize(&self, rendered: String) -> String {
        rendered
            .replace(
                &self.canonical_target_root.display().to_string(),
                "/tmp/phase-target",
            )
            .replace(&self.target_root.display().to_string(), "/tmp/phase-target")
            .replace(&self.target_name, "phase-target")
    }
}

fn hydrate_fix_truth(app: &mut ShellApp, target: &std::path::Path, page: WorkbenchPage) {
    if page != WorkbenchPage::Fix {
        return;
    }
    let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(app) else {
        return;
    };
    let target_revision = app
        .engagement
        .phase_target_snapshot()
        .and_then(|snapshot| snapshot.revision.clone());
    let hydration_target = app.target_owned().unwrap_or_else(|| target.to_path_buf());
    app.hydrate_view_keys_blocking(
        &hydration_target,
        vec![crate::ViewHydrationKey::FindingPatchTruth {
            fingerprint: finding.fingerprint,
            finding_scan_id: finding.scan_id,
            target_revision,
        }],
    );
}

fn reference_app(
    target: &std::path::Path,
    page: WorkbenchPage,
    width: u16,
    height: u16,
) -> ShellApp {
    let workspace = WorkspaceTarget::new(target).expect("phase reference workspace");
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.4".to_string());
    let mut app = ShellApp::new(config, Some(&workspace));
    app.set_viewport(TerminalViewport::new(width, height));
    app.set_input_mode(InputMode::Navigate);
    app.set_shell_view(ShellView::Workbench);
    app.router.workbench_mut().set_page(Some(page));
    app.router.workbench_mut().set_focus(page.primary_surface());
    app
}

fn target_name(target: &std::path::Path) -> String {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("phase-target")
        .to_string()
}
