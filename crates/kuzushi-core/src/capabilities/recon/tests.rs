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
cancellation: None,
authorization: Default::default(),
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
PATH=/usr/bin:/bin
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
            result.get("status").and_then(Value::as_str),
            Some("completed")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with("recon:nmap discovered")));
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
PATH=/usr/bin:/bin
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
        assert!(
            result["data"].get("skippedOutOfScope").is_none(),
            "a verb that takes one target refuses it at dispatch, so it reports no skipped entries"
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
PATH=/usr/bin:/bin
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

    /// A curl stand-in that answers per requested URL and records every URL it
    /// was asked for, so a test can prove which requests were actually sent.
    #[cfg(unix)]
    fn write_recording_curl(path: &Path, log: &Path, cases: &[(&str, &str)]) {
        let branches: String = cases
            .iter()
            .map(|(url, response)| {
                format!(
                    "  {url})\n    cat <<'HTTP'\n{response}\nHTTP\n    ;;\n",
                    url = url,
                    response = response
                )
            })
            .collect();
        write_executable(
            path,
            &format!(
                "#!/bin/sh\nPATH=/usr/bin:/bin\nfor arg in \"$@\"; do url=\"$arg\"; done\n\
                 printf '%s\\n' \"$url\" >> {log}\ncase \"$url\" in\n{branches}  *)\n    \
                 printf 'HTTP/1.1 599 Unexpected\\r\\n\\r\\n'\n    ;;\nesac\n",
                log = log.display(),
                branches = branches
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_fingerprint_registers_the_endpoint_that_answered_the_redirect() {
        // `curl -L` followed redirects and the run still filed the response
        // under the requested target's host, port, and port-guessed scheme, so
        // a service row described an endpoint that had only pointed elsewhere.
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        let log = temp.path().join("requests.log");
        write_recording_curl(
            &binary,
            &log,
            &[
                (
                    "http://www.example.com/",
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com:8443/app\r\n\r\n",
                ),
                (
                    "https://www.example.com:8443/app",
                    "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Acme</title></html>",
                ),
            ],
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"www.example.com","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result.pointer("/data/services/0/port").and_then(Value::as_u64),
            Some(8443)
        );
        assert_eq!(
            result.pointer("/data/services/0/name").and_then(Value::as_str),
            Some("https")
        );
        assert_eq!(
            result.pointer("/data/fingerprint/server").and_then(Value::as_str),
            Some("nginx")
        );
        assert_eq!(
            result
                .pointer("/data/redirects/fetched")
                .and_then(Value::as_array)
                .map(|fetched| fetched
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()),
            Some(vec![
                "http://www.example.com/",
                "https://www.example.com:8443/app"
            ])
        );
        let output = result["output"].as_str().unwrap();
        assert!(
            output.contains("registered https://www.example.com:8443/app as https:8443"),
            "got: {output}"
        );
        assert!(
            output.contains("followed 1 redirect from http://www.example.com/"),
            "got: {output}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_redirect_out_of_scope_is_never_requested() {
        // The dispatch gate weighs only the requested target. Following a
        // redirect with `-L` sent the next request before anything could weigh
        // the host it named, so a redirect reached hosts the program had put
        // out of scope.
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        let log = temp.path().join("requests.log");
        write_recording_curl(
            &binary,
            &log,
            &[(
                "http://www.example.com/",
                "HTTP/1.1 302 Found\r\nLocation: https://cdn.out-of-scope.test/app\r\n\r\n",
            )],
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let scope_dir = temp.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\nhosts = [\"www.example.com\"]\n",
        )
        .unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"www.example.com","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        let requested = fs::read_to_string(&log).unwrap();
        assert_eq!(requested.lines().collect::<Vec<_>>(), vec!["http://www.example.com/"]);
        assert_eq!(
            result
                .pointer("/data/redirects/notFollowed/url")
                .and_then(Value::as_str),
            Some("https://cdn.out-of-scope.test/app")
        );
        assert_eq!(
            result
                .pointer("/data/redirects/notFollowed/reason")
                .and_then(Value::as_str),
            Some("out-of-scope")
        );
        let output = result["output"].as_str().unwrap();
        assert!(
            output.contains(
                "redirect to https://cdn.out-of-scope.test/app not followed: out of scope"
            ),
            "got: {output}"
        );
        // The endpoint that answered is still the requested one.
        assert_eq!(
            result.pointer("/data/services/0/port").and_then(Value::as_u64),
            Some(80)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fingerprint_without_a_redirect_discloses_none() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        let log = temp.path().join("requests.log");
        write_recording_curl(
            &binary,
            &log,
            &[(
                "https://www.example.com/",
                "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Acme</title></html>",
            )],
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

        assert!(result.pointer("/data/redirects").is_none());
        let output = result["output"].as_str().unwrap();
        assert_eq!(
            output,
            "recon:http-fingerprint registered https://www.example.com as https:443"
        );
    }

    #[test]
    fn an_unreadable_target_port_is_refused_before_any_request() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let error = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"www.example.com:99999"}),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("could not read target"), "got: {error}");
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
cancellation: None,
authorization: Default::default(),
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
            binary: binary.display().to_string(),
            timeout_seconds: 10,
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let worker = thread::spawn(move || {
            fingerprinter.fetch("http://example.com/", &worker_cancellation)
        });
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let error = worker.join().unwrap().unwrap_err().to_string();

        assert!(error.contains("cancelled"));
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }

    // ── M2 §2.2: recon intake adapters ──────────────────────────────

    fn import_input(tool: &str, jsonl_path: &Path) -> serde_json::Value {
        json!({"tool": tool, "path": jsonl_path.display().to_string()})
    }

    #[test]
    fn import_amass_jsonl_creates_hosts_with_recorded_sources() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("amass.jsonl");
        fs::write(
            &dump,
            "{\"name\":\"api.lab.test\",\"domain\":\"lab.test\",\"sources\":[\"crtsh\"]}\n\
             {\"name\":\"www.lab.test\",\"domain\":\"lab.test\",\"sources\":[\"wayback\"]}\n",
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("amass", &dump), &ctx)
            .expect("amass import succeeds");

        let hosts = result["data"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(hosts
            .iter()
            .any(|host| host["address"] == "api.lab.test"));
    }

    #[test]
    fn import_httpx_jsonl_creates_host_service_pairs() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("httpx.jsonl");
        fs::write(
            &dump,
            "{\"url\":\"https://api.lab.test\",\"host\":\"api.lab.test\",\"port\":443,\"scheme\":\"https\",\"status_code\":200,\"title\":\"API\",\"tech\":[\"nginx\"]}\n",
        ).unwrap();

        let result = execute_recon_tool("recon:import", import_input("httpx", &dump), &ctx)
            .expect("httpx import succeeds");

        let services = result["data"]["services"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["port"], 443);
        assert_eq!(services[0]["proto"], "tcp");
        assert_eq!(services[0]["name"], "nginx");
    }

    #[test]
    fn import_httpx_derives_common_fields_from_a_url_only_record() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("httpx-url-only.jsonl");
        fs::write(
            &dump,
            "{\"url\":\"https://example.com\",\"status-code\":200,\"title\":\"Example\"}\n",
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("httpx", &dump), &ctx)
            .expect("url-only httpx import succeeds");

        let hosts = result["data"]["hosts"].as_array().unwrap();
        let services = result["data"]["services"].as_array().unwrap();
        let notes = result["data"]["notes"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["address"], "example.com");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["port"], 443);
        assert!(notes
            .iter()
            .any(|note| note["data"]["status_code"] == 200));
        assert!(notes
            .iter()
            .any(|note| note["data"]["imported"] == 1));
    }

    #[test]
    fn import_nuclei_jsonl_creates_notes_with_severity() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("nuclei.jsonl");
        fs::write(
            &dump,
            "{\"template-id\":\"http-missing-security-headers\",\"info\":{\"severity\":\"info\",\"name\":\"missing headers\"},\"matched-at\":\"https://api.lab.test/\",\"host\":\"api.lab.test\"}\n",
        ).unwrap();

        let result = execute_recon_tool("recon:import", import_input("nuclei", &dump), &ctx)
            .expect("nuclei import succeeds");

        let notes = result["data"]["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0]["data"]["template"], "http-missing-security-headers"
        );
    }

    #[test]
    fn import_nmap_xml_creates_host_service_rows() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("nmap.xml");
        fs::write(
            &dump,
            r#"<?xml version="1.0"?>
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="10.0.0.1" addrtype="ipv4" />
                <hostnames><hostname name="lab.test" /></hostnames>
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" product="nginx" />
                  </port>
                </ports>
              </host>
            </nmaprun>"#,
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("nmap-xml", &dump), &ctx)
            .expect("nmap-xml import succeeds");

        let hosts = result["data"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        let services = result["data"]["services"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["port"], 80);
    }

    #[test]
    fn recon_import_refuses_unknown_kind_with_actionable_error() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("anything.jsonl");
        fs::write(&dump, "{}\n").unwrap();
        let err = execute_recon_tool("recon:import", import_input("unsupported", &dump), &ctx)
            .unwrap_err()
            .to_string();
        assert!(err.contains("amass, httpx, nuclei, nmap-xml, burp-xml, har"));
    }

    #[test]
    fn recon_import_har_folds_bounty_evidence_into_the_canonical_route() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("traffic.har");
        fs::write(
            &dump,
            json!({
                "log": {
                    "version": "1.2",
                    "entries": [{
                        "request": {
                            "method": "GET",
                            "url": "https://api.lab.test/health",
                            "headers": []
                        },
                        "response": {"status": 200, "headers": []}
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("har", &dump), &ctx)
            .expect("HAR import succeeds through recon");

        assert_eq!(result["data"]["imported"], 1);
        assert!(result["output"].as_str().unwrap().contains("recon:import har"));
    }

    #[test]
    fn scope_toml_refuses_out_of_scope_recon_target() {
        // M2 §2.1: recon dispatch must refuse OutOfScope targets so
        // operators don't accidentally scan their bounty's deny list.
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let scope_dir = workspace_dir.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\nhosts = [\"*.lab.test\"]\n\
             [out_of_scope]\nhosts = [\"evil.com\"]\n",
        )
        .unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let err = execute_recon_tool(
            "recon:subdomain",
            json!({"domain": "evil.com", "source": "crtsh"}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("out of scope"), "got: {err}");
    }

    #[test]
    fn only_the_nmap_verb_reads_its_target_as_an_address_block() {
        // P1 review: `recon:nmap` hands its target to a scanner whose target
        // specification names a whole block, but `recon:http-fingerprint`
        // hands the same string to curl, which resolves `10.0.0.1-2` as a
        // domain name reaching whatever DNS answers with. Reading it as a
        // covered pair there would admit an asset no rule covers, so the
        // block reading stops at the nmap verb.
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let scope_dir = workspace_dir.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\ncidrs = [\"10.0.0.0/24\"]\n",
        )
        .unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let err = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target": "10.0.0.1-2"}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("out of scope"), "got: {err}");
        // The same target reaches nmap's own binary resolution, so the gate
        // passes it and the run fails on the missing binary instead.
        let err = execute_recon_tool(
            "recon:nmap",
            json!({"target": "10.0.0.1-2", "binary": workspace_dir.path().join("missing-nmap").display().to_string()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("out of scope"), "got: {err}");
    }

    #[test]
    fn recon_import_amass_skips_out_of_scope_hosts_per_entry() {
        // P1 review: `recon:import` requests carry `{tool, path}` and
        // no top-level target, so the dispatch-level scope guard
        // returned None. Each importer must now check every parsed
        // entry against scope.toml. Out-of-scope amass results stay
        // out of the recon store.
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let scope_dir = workspace_dir.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\nhosts = [\"*.lab.test\"]\n\
             [out_of_scope]\nhosts = [\"evil.com\"]\n",
        )
        .unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("amass.jsonl");
        fs::write(
            &dump,
            "{\"name\":\"api.lab.test\",\"sources\":[\"crtsh\"]}\n\
             {\"name\":\"evil.com\",\"sources\":[\"crtsh\"]}\n",
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("amass", &dump), &ctx)
            .expect("amass import succeeds");

        let hosts = result["data"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1, "out-of-scope host must be skipped");
        assert_eq!(hosts[0]["address"], "api.lab.test");
        assert_eq!(result["data"]["skippedOutOfScope"], 1);
        let output = result["output"].as_str().unwrap();
        assert!(
            output.contains("1 out-of-scope skipped"),
            "the scope gate's refusal must reach the operator: {output}"
        );
    }

    fn scoped_workspace(workspace_dir: &Path) -> WorkspaceTarget {
        let scope_dir = workspace_dir.join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[out_of_scope]\nhosts = [\"evil.com\", \"10.0.0.1\"]\n",
        )
        .unwrap();
        WorkspaceTarget::new(workspace_dir).unwrap()
    }

    #[test]
    fn recon_import_nuclei_discloses_the_entries_scope_refused() {
        // The counter was incremented and then dropped: `into_report` never
        // carried it and the output line said only "completed for <path>", so
        // a dump the scope file denied entirely read as a clean import.
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = scoped_workspace(workspace_dir.path());
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("nuclei.jsonl");
        fs::write(
            &dump,
            "{\"template-id\":\"exposed-panel\",\"info\":{\"severity\":\"high\"},\"host\":\"evil.com\"}\n",
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("nuclei", &dump), &ctx)
            .expect("nuclei import succeeds");

        assert!(result["data"]["notes"].as_array().unwrap().is_empty());
        assert_eq!(result["data"]["skippedOutOfScope"], 1);
        let output = result["output"].as_str().unwrap();
        assert_eq!(
            output,
            format!(
                "recon:import nuclei imported nothing from {} · 1 out-of-scope skipped",
                dump.display()
            ),
            "an import that landed nothing must not read as a completed one"
        );
    }

    #[test]
    fn recon_import_nmap_xml_discloses_the_hosts_scope_refused() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = scoped_workspace(workspace_dir.path());
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("nmap.xml");
        fs::write(
            &dump,
            r#"<?xml version="1.0"?>
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="10.0.0.1" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" />
                  </port>
                </ports>
              </host>
              <host>
                <status state="up" />
                <address addr="10.0.0.2" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" />
                  </port>
                </ports>
              </host>
            </nmaprun>"#,
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("nmap-xml", &dump), &ctx)
            .expect("nmap-xml import succeeds");

        let hosts = result["data"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["address"], "10.0.0.2");
        assert_eq!(result["data"]["skippedOutOfScope"], 1);
        let output = result["output"].as_str().unwrap();
        assert!(
            output.starts_with("recon:import nmap-xml imported 1 host, 1 service from"),
            "the output must name what landed: {output}"
        );
        assert!(output.ends_with(" · 1 out-of-scope skipped"), "got: {output}");
    }

    #[test]
    fn a_complete_recon_import_names_its_rows_and_discloses_no_skips() {
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("amass.jsonl");
        fs::write(
            &dump,
            "{\"name\":\"api.lab.test\",\"sources\":[\"crtsh\"]}\n\
             {\"name\":\"www.lab.test\",\"sources\":[\"crtsh\"]}\n",
        )
        .unwrap();

        let result = execute_recon_tool("recon:import", import_input("amass", &dump), &ctx)
            .expect("amass import succeeds");

        assert_eq!(result["data"]["skippedOutOfScope"], 0);
        let output = result["output"].as_str().unwrap();
        assert_eq!(
            output,
            format!(
                "recon:import amass imported 2 hosts, 1 note from {}",
                dump.display()
            ),
            "nothing was skipped, so nothing is disclosed"
        );
    }


    #[test]
    fn recon_import_nmap_xml_skips_non_open_ports() {
        // P2 review: nmap XML carries closed/filtered ports alongside
        // open ones. The importer documents it should keep only open
        // ports — this regression locks the filter in so future
        // refactors can't silently re-pollute the recon view.
        let workspace_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(workspace_dir.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let dump = workspace_dir.path().join("nmap.xml");
        fs::write(
            &dump,
            r#"<?xml version="1.0"?>
            <nmaprun>
              <host>
                <status state="up" />
                <address addr="10.0.0.1" addrtype="ipv4" />
                <ports>
                  <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" />
                  </port>
                  <port protocol="tcp" portid="22">
                    <state state="filtered" />
                    <service name="ssh" />
                  </port>
                  <port protocol="tcp" portid="443">
                    <state state="closed" />
                    <service name="https" />
                  </port>
                </ports>
              </host>
            </nmaprun>"#,
        )
        .unwrap();

        let result =
            execute_recon_tool("recon:import", import_input("nmap-xml", &dump), &ctx)
                .expect("nmap-xml import succeeds");

        let services = result["data"]["services"].as_array().unwrap();
        assert_eq!(services.len(), 1, "only the open port should land");
        assert_eq!(services[0]["port"], 80);
    }
}
