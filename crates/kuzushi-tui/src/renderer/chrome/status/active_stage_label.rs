use super::*;

pub(crate) fn active_stage_label(app: &ShellApp) -> Option<&'static str> {
    if let Some(scan) = app.scan.as_ref() {
        if scan.running {
            if scan.abort_requested {
                return Some("aborting");
            }
            return Some("running");
        }
    }
    if let Some(agent) = app.agent_chat.as_ref() {
        if agent.running {
            if agent.abort_requested {
                return Some("aborting");
            }
            return Some("asking");
        }
    }
    if app.planner_running {
        if app.plan_abort_requested {
            return Some("aborting");
        }
        return Some("planning");
    }
    if app.threat_worker_running {
        if app.threat_abort_requested {
            return Some("aborting");
        }
        return Some("modeling");
    }
    None
}
