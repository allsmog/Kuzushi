use super::*;

pub(crate) fn handle_scan_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Scan(target) = command else {
        return false;
    };
    app.open_guided_scan(target.clone());
    true
}

pub(crate) fn handle_demo_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Demo = command else {
        return false;
    };
    match prepare_demo_fixture() {
        Ok(demo_dir) => {
            app.log(
                "demo",
                format!(
                    "offline fixture ready at {} — deterministic engines only; no key or model required",
                    demo_dir.display()
                ),
            );
            app.start_umbrella_sast_scan(Some(demo_dir));
        }
        Err(error) => app.log("error", format!("could not prepare demo fixture: {error}")),
    }
    true
}

fn prepare_demo_fixture() -> std::io::Result<std::path::PathBuf> {
    let demo_dir = std::env::temp_dir().join("kuzushi-demo");
    if demo_dir.exists() {
        std::fs::remove_dir_all(&demo_dir)?;
    }
    std::fs::create_dir_all(&demo_dir)?;
    std::fs::write(
        demo_dir.join("config.env"),
        "# production credentials accidentally committed\n\
         AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
         AWS_SECRET_ACCESS_KEY=wJalrXUtnFE/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
         GITHUB_TOKEN=ghp_x7rT9qLm2KvW8pYzN3jBdF5cH1aG6eQ4sU0i\n",
    )?;
    std::fs::write(
        demo_dir.join("Dockerfile"),
        "FROM node:latest\n\
         ADD https://example.com/setup.sh /setup.sh\n\
         COPY . .\n\
         RUN npm install\n\
         CMD [\"node\", \"server.js\"]\n",
    )?;
    Ok(demo_dir)
}

pub(crate) fn handle_model_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Model(model) = command else {
        return false;
    };
    app.handle_model_command(model.clone());
    true
}

pub(crate) fn handle_auth_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Auth = command else {
        return false;
    };
    app.show_auth_status();
    true
}

pub(crate) fn handle_auth_login_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::AuthLogin(provider) = command else {
        return false;
    };
    app.handle_auth_login_command(provider.clone());
    true
}

pub(crate) fn handle_provider_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Provider(provider) = command else {
        return false;
    };
    app.handle_provider_command(provider.clone());
    true
}

pub(crate) fn handle_backend_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Backend(backend) = command else {
        return false;
    };
    app.handle_backend_command(backend.clone());
    true
}

pub(crate) fn handle_cost_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Cost = command else {
        return false;
    };
    app.show_cost_status();
    true
}

pub(crate) fn handle_config_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Config = command else {
        return false;
    };
    app.shell_view = ShellView::Config;
    app.sync_selected_model_index();
    app.log(
        "config",
        format!(
            "runtime={} provider={} model={}",
            runtime_backend_label(&app.config),
            app.provider_label(),
            app.config
                .model
                .as_deref()
                .map(display_model_selector)
                .unwrap_or_else(|| "unconfigured".to_string())
        ),
    );
    true
}

pub(crate) fn handle_permissions_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Permissions = command else {
        return false;
    };
    app.shell_view = ShellView::Config;
    app.log(
        "permissions",
        "model fallback forbidden without explicit consent; headless run requires explicit tool names",
    );
    app.log(
        "permissions",
        "network egress, filesystem writes outside staged flows, and destructive actions require approval; denial leaves state unchanged",
    );
    true
}

pub(crate) fn handle_use_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Use(module) = command else {
        return false;
    };
    if app
        .registry
        .modules()
        .any(|entry| entry.metadata().id == module.as_str())
    {
        app.focused_module = Some(module.clone());
        app.shell_view = ShellView::Module;
        app.log("use", module);
    } else {
        app.log("error", app.unknown_module_message(module));
    }
    true
}

pub(crate) fn handle_tune_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tune = command else {
        return false;
    };
    app.shell_view = ShellView::Tune;
    app.log("view", "tune");
    true
}
