#[cfg(test)]
mod tests {
    use std::fs;
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::super::*;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, content: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, content).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn parses_nmap_grepable_output() {
        let parsed = parse_nmap_grepable(
            "Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/\n",
        )
        .unwrap();

        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].address, "192.0.2.10");
        assert_eq!(parsed.hosts[0].hostname.as_deref(), Some("web.example"));
        assert_eq!(parsed.hosts[0].services.len(), 2);
        assert_eq!(parsed.hosts[0].services[0].port, 80);
        assert_eq!(parsed.hosts[0].services[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn parses_subdomain_sources() {
        let crtsh = parse_crtsh_subdomains(
            r#"[{"name_value":"www.example.com\n*.api.example.com\nexample.com"}]"#,
            "example.com",
        )
        .unwrap();
        assert_eq!(crtsh, vec!["api.example.com", "www.example.com"]);

        let wayback = parse_wayback_subdomains(
            r#"[["original"],["https://shop.example.com/a"],["https://www.example.com/b"]]"#,
            "example.com",
        )
        .unwrap();
        assert_eq!(wayback, vec!["shop.example.com", "www.example.com"]);
    }

    #[test]
    fn parses_http_fingerprint_headers_and_body() {
        let parsed = parse_http_fingerprint(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: Express\r\n\r\n<html><title>Acme</title><script src=\"/_next/static/app.js\"></script></html>",
        )
        .unwrap();

        assert_eq!(parsed.status, Some(200));
        assert_eq!(parsed.server.as_deref(), Some("nginx"));
        assert_eq!(parsed.title.as_deref(), Some("Acme"));
        assert!(parsed.technologies.contains(&"nginx".to_string()));
        assert!(parsed.technologies.contains(&"Express".to_string()));
        assert!(parsed.technologies.contains(&"next.js".to_string()));
    }

    #[test]
    fn recon_store_lists_notes_with_optional_type_filter() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();

        store
            .create_note(&workspace_id, None, None, "http", json!({"title":"web"}))
            .unwrap();
        store
            .create_note(&workspace_id, None, None, "dns", json!({"title":"dns"}))
            .unwrap();

        assert_eq!(store.list_notes(&workspace_id, None).unwrap().len(), 2);
        let http = store.list_notes(&workspace_id, Some("http")).unwrap();
        assert_eq!(http.len(), 1);
        assert_eq!(http[0].ntype, "http");
    }

    #[cfg(unix)]
    #[test]
    fn nmap_executor_invokes_subprocess_and_persists_workspace_rows() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("nmap");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:nmap",
            json!({"target":"192.0.2.10","ports":"80,443","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            result
                .pointer("/data/services/1/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        assert_eq!(store.list_hosts(&workspace_id).unwrap().len(), 1);
        assert_eq!(
            store
                .list_services_for_host(
                    result
                        .pointer("/data/hosts/0/id")
                        .and_then(Value::as_str)
                        .unwrap()
                )
                .unwrap()
                .len(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn subdomain_executor_invokes_curl_and_persists_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'JSON'
[{"name_value":"www.example.com\napi.example.com"}]
JSON
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:subdomain",
            json!({"domain":"example.com","source":"crtsh","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result.pointer("/data/subdomains/0").and_then(Value::as_str),
            Some("api.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/hosts")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            result
                .pointer("/data/notes/0/ntype")
                .and_then(Value::as_str),
            Some("recon:subdomain")
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_fingerprint_executor_invokes_curl_and_persists_service() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"https://www.example.com","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/services/0/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        assert_eq!(
            result
                .pointer("/data/fingerprint/server")
                .and_then(Value::as_str),
            Some("nginx")
        );
    }

    #[test]
    fn missing_nmap_binary_error_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let error = execute_recon_tool(
            "recon:nmap",
            json!({"target":"192.0.2.10","binary":temp.path().join("missing-nmap").display().to_string()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("could not find subprocess binary"));
        assert!(error.contains("Install nmap"));
    }

    #[test]
    fn missing_subdomain_binary_error_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let error = execute_recon_tool(
            "recon:subdomain",
            json!({"domain":"example.com","source":"crtsh","binary":temp.path().join("missing-curl").display().to_string()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("could not find subprocess binary"));
        assert!(error.contains("Install curl"));
    }

    #[test]
    fn missing_workspace_error_is_actionable() {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };
        let error = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"example.com"}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("active workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_nmap_process() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("slow-nmap");
        write_executable(
            &binary,
            "#!/bin/sh\nsleep 5\nprintf 'Host: 192.0.2.10 () Ports: 80/open/tcp//http///\\n'\n",
        );
        let scanner = ReconNmapScanner {
            target: "192.0.2.10".to_string(),
            ports: "80".to_string(),
            binary: binary.display().to_string(),
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan(&worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let error = worker.join().unwrap().unwrap_err().to_string();

        assert!(error.contains("cancelled"));
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_http_fingerprint_process() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("slow-curl");
        write_executable(
            &binary,
            "#!/bin/sh\nsleep 5\nprintf 'HTTP/1.1 200 OK\\n\\n'\n",
        );
        let fingerprinter = ReconHttpFingerprinter {
            target: "http://example.com".to_string(),
            binary: binary.display().to_string(),
            timeout_seconds: 10,
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let worker = thread::spawn(move || fingerprinter.fingerprint(&worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let error = worker.join().unwrap().unwrap_err().to_string();

        assert!(error.contains("cancelled"));
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }
}
