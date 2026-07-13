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

    #[test]
    fn terminal_plan_event_settles_matching_activity_once() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new("plan-cost")));
        let cost = kuzushi_core::runtime::RuntimeCost::from_usd(0.025, "plan cost").unwrap();
        let event = || PlanEvent::Failed {
            error: "fixture failure".to_string(),
            audit: AgentCallAudit::test()
                .with_cost(kuzushi_core::runtime::RuntimeCostReport::known(cost)),
        };

        app.apply_plan_event(event());
        app.apply_plan_event(event());

        assert_eq!(app.session().session_cost_usd(), 0.025);
        assert_eq!(
            app.activity()
                .unwrap()
                .runtime_cost_report()
                .unwrap()
                .exact_usd(),
            Some(0.025)
        );
    }
}
