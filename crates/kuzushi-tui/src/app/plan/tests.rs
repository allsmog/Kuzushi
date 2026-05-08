#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn start_planner_reports_empty_running_and_missing_model_without_spawning() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.start_planner("   ");
        assert!(app.log.iter().any(|line| line.prefix == "error"));

        app.log.clear();
        app.planner_running = true;
        app.start_planner("check auth");
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("planner already running")));

        app.log.clear();
        app.planner_running = false;
        app.start_planner("check auth");
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("requires an explicit model")));
    }
}
