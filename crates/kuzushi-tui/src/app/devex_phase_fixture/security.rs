use super::*;

pub(super) fn seed(app: &mut ShellApp) {
    seed_flow(app);
    seed_chain(app);
    seed_patch(app);
}

fn seed_flow(app: &mut ShellApp) {
    let selected = app.findings()[0].clone();
    app.domain_mut().set_taint_flows(vec![TaintFlowSnapshot {
        finding_fingerprint: Some(selected.fingerprint),
        finding_identity_id: selected.identity_id,
        cwe: "CWE-89".to_string(),
        severity: "high".to_string(),
        stages: flow_stages(),
    }]);
}

fn flow_stages() -> Vec<TaintStage> {
    vec![
        TaintStage {
            message: "HTTP query parameter".to_string(),
            file: "src/auth/login.rs".to_string(),
            line: 12,
            snippet: Some("let user = request.query(\"user\")".to_string()),
        },
        TaintStage {
            message: "database query sink".to_string(),
            file: "src/auth/login.rs".to_string(),
            line: 17,
            snippet: Some("query(user)".to_string()),
        },
    ]
}

fn seed_chain(app: &mut ShellApp) {
    app.domain_mut()
        .set_exploit_chains(vec![ExploitChainDetail {
            id: "C-0001".to_string(),
            title: "Unauthenticated query manipulation".to_string(),
            severity: ChainSeverity::Critical,
            narrative: Some("request input reaches a privileged query".to_string()),
            impact_description: Some("read protected account data".to_string()),
            preconditions: vec!["public login route".to_string()],
            steps: chain_steps(),
        }]);
}

fn chain_steps() -> Vec<ExploitChainStep> {
    vec![
        ExploitChainStep {
            role: "entry".to_string(),
            description: "supply crafted query parameter".to_string(),
            file: "src/auth/login.rs".to_string(),
            line: 12,
        },
        ExploitChainStep {
            role: "impact".to_string(),
            description: "alter database predicate".to_string(),
            file: "src/auth/login.rs".to_string(),
            line: 17,
        },
    ]
}

fn seed_patch(app: &mut ShellApp) {
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "bind the user value as a query parameter".to_string(),
        side_effect: Some("preserves the login response schema".to_string()),
        diff: "- query(user)\n+ query_bind(user)".to_string(),
        tests: vec![(
            "login_rejects_sqli".to_string(),
            "payload is inert".to_string(),
        )],
        guardrail: Some("human approval required".to_string()),
        staged_at: Some(".kuzushi/v3/runs/patch-phase-run/patch.diff".to_string()),
    });
}
