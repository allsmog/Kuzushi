use super::*;
use kuzushi_core::{ReconHost, V2Config};

#[test]
fn recent_module_activity_model_prefers_recon_snapshot() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.recon_snapshot = Some(recon_snapshot());
    app.log("result", "recon:nmap stale fallback line");

    let model = recent_module_activity_model(&app, "recon", 8);

    assert_eq!(
        model.rows.first(),
        Some(&ModuleActivityRow::ReconService {
            host: "acme-checkout.com".to_string(),
            port: 443,
            service: "https".to_string(),
            banner: "nginx/1.24".to_string(),
        })
    );
}

#[test]
fn recent_module_activity_model_falls_back_to_log() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log(
        "result",
        "recon:nmap discovered 1 host\nrecon:nmap found 2 services",
    );

    let model = recent_module_activity_model(&app, "recon", 8);

    assert_eq!(model.rows.len(), 2);
    assert_eq!(
        model.rows.first(),
        Some(&ModuleActivityRow::Transcript {
            prefix: "result".to_string(),
            body: "recon:nmap discovered 1 host".to_string(),
        })
    );
}

fn recon_snapshot() -> ReconSnapshot {
    ReconSnapshot {
        hosts: vec![ReconHost {
            id: "h1".to_string(),
            workspace_id: "ws".to_string(),
            address: "192.0.2.10".to_string(),
            hostname: Some("acme-checkout.com".to_string()),
            state: "alive".to_string(),
        }],
        services: vec![ReconService {
            id: "s1".to_string(),
            host_id: "h1".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            name: Some("https".to_string()),
            banner: Some("nginx/1.24".to_string()),
            state: "open".to_string(),
        }],
        notes: Vec::new(),
        last_tool: Some("recon:nmap".to_string()),
        last_target: Some("acme-checkout.com".to_string()),
    }
}
