#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn start_planner_reports_empty_running_and_missing_model_without_spawning() {
        let mut app = ShellApp::new(V2Config::default(), None);

        update_and_execute_effects(&mut app, Msg::Cmd(ShellCommand::Plan("   ".to_string())));
        assert!(app.log_lines().iter().any(|line| line.prefix == "error"));

        app.clear_log();
        app.set_planner_running(true);
        update_and_execute_effects(
            &mut app,
            Msg::Cmd(ShellCommand::Plan("check auth".to_string())),
        );
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("planner already running")));

        app.clear_log();
        app.set_planner_running(false);
        update_and_execute_effects(
            &mut app,
            Msg::Cmd(ShellCommand::Plan("check auth".to_string())),
        );
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit model")));
    }
}
