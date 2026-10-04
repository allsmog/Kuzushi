use super::*;
use std::os::unix::fs::PermissionsExt;

fn server(script: &str) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("server");
    std::fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    (directory, binary.to_string_lossy().into_owned())
}

#[tokio::test]
async fn silent_server_times_out_is_reaped_and_cannot_be_reused() {
    let (_directory, binary) = server("read -r request\nsleep 60");
    let client = McpClient::spawn(&binary).await.unwrap();
    let error = client
        .request_with_deadline("initialize", json!({}), Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"), "{error:#}");
    assert!(client.child.lock().await.try_wait().unwrap().is_some());
    assert!(client
        .request("tools/list", json!({}))
        .await
        .unwrap_err()
        .to_string()
        .contains("retired"));
}

#[tokio::test]
async fn oversized_unterminated_response_is_refused() {
    let (_directory, binary) =
        server("read -r request\nhead -c 4194306 /dev/zero | tr '\\000' x\nsleep 60");
    let client = McpClient::spawn(&binary).await.unwrap();
    let error = client
        .request_with_deadline("tools/list", json!({}), Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds 4 MiB"), "{error:#}");
    assert!(client.child.lock().await.try_wait().unwrap().is_some());
}

#[tokio::test]
async fn notification_storm_is_bounded_without_recursive_reads() {
    let (_directory, binary) = server("read -r request\ni=0\nwhile [ $i -lt 200 ]; do echo '{\"jsonrpc\":\"2.0\",\"method\":\"progress\"}'; i=$((i+1)); done\nsleep 60");
    let client = McpClient::spawn(&binary).await.unwrap();
    let error = client.request("tools/list", json!({})).await.unwrap_err();
    assert!(error.to_string().contains("128-frame"), "{error:#}");
}

#[tokio::test]
async fn cancelling_the_request_retires_and_terminates_the_server() {
    let (_directory, binary) = server("read -r request\nsleep 60");
    let client = std::sync::Arc::new(McpClient::spawn(&binary).await.unwrap());
    let task_client = client.clone();
    let task = tokio::spawn(async move { task_client.request("initialize", json!({})).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(client.retired.load(Ordering::SeqCst));
    tokio::time::timeout(Duration::from_secs(2), client.child.lock().await.wait())
        .await
        .unwrap()
        .unwrap();
    client.shutdown().await.unwrap();
}
