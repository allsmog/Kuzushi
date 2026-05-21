use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PwnDashboardModel {
    pub(crate) target: String,
    pub(crate) binary: String,
    pub(crate) state: String,
    pub(crate) profile_status: String,
    pub(crate) auto_round_status: String,
    pub(crate) primitives: Vec<PwnPrimitiveRow>,
    pub(crate) rounds: Vec<PwnRoundRow>,
    pub(crate) reverse_observations: Vec<PwnReverseObservationRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PwnPrimitiveRow {
    pub(crate) kind: String,
    pub(crate) confidence: String,
    pub(crate) remote: String,
    pub(crate) evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PwnRoundRow {
    pub(crate) round: u64,
    pub(crate) actions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PwnReverseObservationRow {
    pub(crate) status: String,
    pub(crate) function: String,
    pub(crate) dangerous_io: usize,
    pub(crate) excerpt: Option<String>,
}

pub(crate) fn pwn_dashboard_model(app: &ShellApp) -> PwnDashboardModel {
    let view = &app.pwn_view;
    PwnDashboardModel {
        target: path_or_dash(view.target.as_ref()),
        binary: path_or_dash(view.binary.as_ref()),
        state: path_or_dash(view.state_path.as_ref()),
        profile_status: profile_status(view.profile_snapshot.as_ref()),
        auto_round_status: auto_round_status(view.auto_solve_snapshot.as_ref()),
        primitives: primitive_rows(view.state_snapshot.as_ref()),
        rounds: round_rows(view.auto_solve_snapshot.as_ref()),
        reverse_observations: reverse_observation_rows(&view.reverse_snapshots),
    }
}

fn primitive_rows(state: Option<&serde_json::Value>) -> Vec<PwnPrimitiveRow> {
    state
        .and_then(|state| state.get("primitives"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(8)
        .map(primitive_row)
        .collect()
}

fn primitive_row(primitive: &serde_json::Value) -> PwnPrimitiveRow {
    PwnPrimitiveRow {
        kind: string_field(primitive, "kind", "unknown"),
        confidence: primitive_confidence(primitive),
        remote: primitive_remote_label(primitive),
        evidence: string_field(primitive, "evidence", ""),
    }
}

fn primitive_confidence(primitive: &serde_json::Value) -> String {
    primitive
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "-".to_string())
}

fn primitive_remote_label(primitive: &serde_json::Value) -> String {
    primitive
        .get("remoteSafe")
        .or_else(|| primitive.get("remote_safe"))
        .and_then(serde_json::Value::as_bool)
        .map(|value| if value { "remote-safe" } else { "local-only" })
        .unwrap_or("unknown")
        .to_string()
}

fn round_rows(auto: Option<&serde_json::Value>) -> Vec<PwnRoundRow> {
    auto.and_then(|auto| auto.pointer("/llmPlanner/iterations"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(6)
        .map(round_row)
        .collect()
}

fn round_row(iteration: &serde_json::Value) -> PwnRoundRow {
    PwnRoundRow {
        round: iteration
            .get("round")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        actions: round_actions(iteration),
    }
}

fn round_actions(iteration: &serde_json::Value) -> String {
    iteration
        .pointer("/decision/actions")
        .and_then(serde_json::Value::as_array)
        .map(|actions| action_labels(actions))
        .unwrap_or_else(|| "-".to_string())
}

fn action_labels(actions: &[serde_json::Value]) -> String {
    actions
        .iter()
        .filter_map(action_label)
        .collect::<Vec<_>>()
        .join(", ")
}

fn reverse_observation_rows(snapshots: &[serde_json::Value]) -> Vec<PwnReverseObservationRow> {
    snapshots
        .iter()
        .rev()
        .take(5)
        .map(reverse_observation_row)
        .collect()
}

fn reverse_observation_row(snapshot: &serde_json::Value) -> PwnReverseObservationRow {
    PwnReverseObservationRow {
        status: reverse_status(snapshot),
        function: string_field(snapshot, "function", "whole binary"),
        dangerous_io: snapshot
            .get("dangerousIo")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        excerpt: snapshot
            .pointer("/revng/output")
            .and_then(serde_json::Value::as_str)
            .map(|value| value.trim().to_string()),
    }
}

fn reverse_status(snapshot: &serde_json::Value) -> String {
    snapshot
        .pointer("/revng/ok")
        .and_then(serde_json::Value::as_bool)
        .map(|value| if value { "revng ok" } else { "revng error" })
        .unwrap_or("revng n/a")
        .to_string()
}

fn action_label(action: &serde_json::Value) -> Option<String> {
    let operation = action.get("operation")?.as_str()?;
    let function = action.get("function").and_then(serde_json::Value::as_str);
    Some(match function {
        Some(function) => format!("{operation}:{function}"),
        None => operation.to_string(),
    })
}

fn profile_status(profile: Option<&serde_json::Value>) -> String {
    profile
        .map(|profile| {
            let arch = string_field(profile, "arch", "unknown arch");
            let needed = profile
                .get("needed")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            format!("{arch} · {needed} needed librar(y/ies)")
        })
        .unwrap_or_else(|| "not run".to_string())
}

fn auto_round_status(auto: Option<&serde_json::Value>) -> String {
    auto.and_then(|auto| auto.pointer("/llmPlanner/iterations"))
        .and_then(serde_json::Value::as_array)
        .map(|items| format!("{} iteration(s)", items.len()))
        .unwrap_or_else(|| "not run".to_string())
}

fn path_or_dash(path: Option<&std::path::PathBuf>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn string_field(value: &serde_json::Value, field: &str, fallback: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwn_dashboard_model_shapes_json_snapshots_for_renderer() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.pwn_view.target = Some(std::path::PathBuf::from("./chal"));
        app.pwn_view.profile_snapshot = Some(serde_json::json!({
            "arch": "x86_64",
            "needed": ["libc.so.6"]
        }));
        app.pwn_view.state_snapshot = Some(serde_json::json!({
            "primitives": [{
                "kind": "stack-write",
                "confidence": 0.875,
                "remote_safe": true,
                "evidence": "memcpy length is attacker-controlled"
            }]
        }));
        app.pwn_view.auto_solve_snapshot = Some(serde_json::json!({
            "llmPlanner": {"iterations": [{
                "round": 2,
                "decision": {"actions": [{"operation": "reverse", "function": "main"}]}
            }]}
        }));
        app.pwn_view.reverse_snapshots.push(serde_json::json!({
            "function": "main",
            "dangerousIo": ["read"],
            "revng": {"ok": true, "output": "call memcpy"}
        }));

        let model = pwn_dashboard_model(&app);

        assert_eq!(model.target, "./chal");
        assert_eq!(model.profile_status, "x86_64 · 1 needed librar(y/ies)");
        assert_eq!(model.auto_round_status, "1 iteration(s)");
        assert_eq!(model.primitives[0].confidence, "0.88");
        assert_eq!(model.primitives[0].remote, "remote-safe");
        assert_eq!(model.rounds[0].actions, "reverse:main");
        assert_eq!(model.reverse_observations[0].status, "revng ok");
    }
}
