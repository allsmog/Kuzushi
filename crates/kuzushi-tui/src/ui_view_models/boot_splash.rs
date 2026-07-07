use crate::{
    build_provenance, BootSplashCheck, BootSplashCheckState, BootSplashSnapshot, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootSplashModel {
    pub(crate) version_line: String,
    pub(crate) checks: Vec<BootSplashCheck>,
    pub(crate) primary_hint: String,
    pub(crate) secondary_hint: String,
}

pub(crate) fn boot_splash_model(app: &ShellApp) -> BootSplashModel {
    app.boot_splash_snapshot()
        .cloned()
        .map(BootSplashModel::from)
        .unwrap_or_else(|| default_boot_splash_model(app))
}

impl From<BootSplashSnapshot> for BootSplashModel {
    fn from(snapshot: BootSplashSnapshot) -> Self {
        Self {
            version_line: snapshot.version_line,
            checks: snapshot.checks,
            primary_hint: snapshot.primary_hint,
            secondary_hint: snapshot.secondary_hint,
        }
    }
}

fn default_boot_splash_model(app: &ShellApp) -> BootSplashModel {
    let provenance = build_provenance();
    BootSplashModel {
        version_line: format!(
            "v{}  ·  {}  ·  channel {}",
            provenance.version,
            build_git_cell(provenance.git_sha, provenance.dirty),
            provenance.profile
        ),
        checks: default_boot_checks(app),
        primary_hint:
            "press ? for help · type /catalog for the menu · /doctor if anything looks off"
                .to_string(),
        secondary_hint: "ctrl-c quits · config + history persist across sessions".to_string(),
    }
}

fn default_boot_checks(app: &ShellApp) -> Vec<BootSplashCheck> {
    vec![
        BootSplashCheck::new(BootSplashCheckState::Ok, "config", "operator config loaded"),
        workspace_check(app),
        model_check(app),
        BootSplashCheck::new(
            BootSplashCheckState::Wait,
            "context-snapshot",
            "not built yet · run context status",
        ),
        BootSplashCheck::new(
            BootSplashCheckState::Wait,
            "auth",
            "not inspected here · run /auth",
        ),
        BootSplashCheck::new(
            BootSplashCheckState::Wait,
            "plugins",
            "not enumerated here · run /tools",
        ),
    ]
}

fn workspace_check(app: &ShellApp) -> BootSplashCheck {
    match app.target() {
        Some(path) => BootSplashCheck::new(
            BootSplashCheckState::Ok,
            "workspace",
            path.display().to_string(),
        ),
        None => BootSplashCheck::new(
            BootSplashCheckState::Wait,
            "workspace",
            "none selected · run target <path>",
        ),
    }
}

fn model_check(app: &ShellApp) -> BootSplashCheck {
    match app.config().model.as_deref() {
        Some(model) => BootSplashCheck::new(BootSplashCheckState::Ok, "model", model),
        None => BootSplashCheck::new(
            BootSplashCheckState::Err,
            "model",
            "not configured · run model",
        ),
    }
}

fn build_git_cell(git_sha: &str, dirty: bool) -> String {
    if dirty {
        format!("{git_sha}+dirty")
    } else {
        git_sha.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn boot_splash_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_boot_splash_snapshot_for_test(Some(BootSplashSnapshot {
            version_line: "v-snapshot".to_string(),
            checks: vec![BootSplashCheck::new(
                BootSplashCheckState::Ok,
                "config",
                "loaded",
            )],
            primary_hint: "primary".to_string(),
            secondary_hint: "secondary".to_string(),
        }));

        let model = boot_splash_model(&app);

        assert_eq!(model.version_line, "v-snapshot");
        assert_eq!(model.primary_hint, "primary");
        assert_eq!(model.checks.len(), 1);
    }
}
