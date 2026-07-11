use super::*;
use std::path::Path;

const DEVEX_PHASE_FIXTURE_ENV: &str = "KUZUSHI_DEVEX_PHASE_FIXTURE";

mod activity;
mod artifacts;
mod findings;
mod security;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhaseFixtureLifecycle {
    Live,
    Settled,
}

pub(crate) fn seed_pdf_phase_reference_fixture(
    app: &mut ShellApp,
    target: &Path,
    lifecycle: PhaseFixtureLifecycle,
) -> Result<(), String> {
    artifacts::seed_files(target)?;
    app.workbench_cache()
        .borrow_mut()
        .invalidate_workspace_files();
    app.hydrate_active_view_blocking();
    artifacts::seed_context(app, target)?;
    findings::seed(app, target)?;
    hydrate_reference_security_artifacts(app, target);
    security::seed(app);
    activity::seed(app, lifecycle);
    Ok(())
}

fn hydrate_reference_security_artifacts(app: &mut ShellApp, target: &Path) {
    let hydration_target = app.target_owned().unwrap_or_else(|| target.to_path_buf());
    app.hydrate_view_keys_blocking(
        &hydration_target,
        vec![
            ViewHydrationKey::JsonFile {
                path: kuzushi_core::capabilities::persistent_threat_model_path(&hydration_target),
            },
            ViewHydrationKey::RunArtifactText {
                run_id: "verify-phase-run".to_string(),
                leaf: "trace.jsonl".to_string(),
            },
        ],
    );
}

impl ShellApp {
    pub(crate) fn seed_devex_phase_fixture_if_requested(&mut self) {
        let value = std::env::var(DEVEX_PHASE_FIXTURE_ENV).ok();
        self.seed_devex_phase_fixture_for_value(value.as_deref());
    }

    fn seed_devex_phase_fixture_for_value(&mut self, value: Option<&str>) {
        let Some(lifecycle) = devex_phase_fixture_lifecycle(value) else {
            return;
        };
        let Some(target) = self.target_owned() else {
            self.log("devex", "PDF phase fixture needs an active target");
            return;
        };
        if !is_offline_demo_target(&target) {
            self.log(
                "devex",
                "PDF phase fixture refused: active target is not the offline demo",
            );
            return;
        }
        match seed_pdf_phase_reference_fixture(self, &target, lifecycle) {
            Ok(()) => {
                self.set_info_notice("devex", "PDF phase reference fixture loaded");
                self.log("devex", "PDF phase reference fixture loaded");
            }
            Err(error) => self.log(
                "error",
                format!("could not load PDF phase reference fixture: {error}"),
            ),
        }
    }
}

fn is_offline_demo_target(target: &Path) -> bool {
    let expected = std::env::temp_dir().join("kuzushi-demo");
    let safe_directory = std::fs::symlink_metadata(&expected)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    safe_directory
        && target
            .canonicalize()
            .ok()
            .zip(expected.canonicalize().ok())
            .is_some_and(|(target, expected)| target == expected)
}

#[cfg(test)]
fn devex_phase_fixture_requested(value: Option<&str>) -> bool {
    devex_phase_fixture_lifecycle(value).is_some()
}

fn devex_phase_fixture_lifecycle(value: Option<&str>) -> Option<PhaseFixtureLifecycle> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "live" => Some(PhaseFixtureLifecycle::Live),
        "1" | "true" | "yes" | "on" | "settled" => Some(PhaseFixtureLifecycle::Settled),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
