//! Real model calls for the PoC via the locally authenticated `claude` CLI
//! (headless `-p`, stream-json). Isolated from the operator's MCP servers,
//! settings, and skills so each turn only carries what we send; read-only
//! tools (Read/Grep/Glob) let the model ground answers in the repository and
//! attached files. The model is whatever `claude` is configured to use — the
//! PoC never names one.
//!
//! The shipped feature routes through Kuzushi's own runtime instead
//! (`AskRequest::threat_model(q, true)` → `reduce_ask_agent`).

use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

pub struct AiRequest {
    pub system_prompt: String,
    pub prompt: String,
    pub cwd: PathBuf,
    pub add_dirs: Vec<PathBuf>,
    pub resume: Option<String>,
    pub purpose: Purpose,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Purpose {
    Chat,
    Refine,
}

pub enum AiEvent {
    Tool(String),
    Done { purpose: Purpose, text: String, session_id: Option<String>, cost_usd: f64, duration_ms: u64 },
    Failed { purpose: Purpose, error: String },
}

pub type ChildSlot = Arc<Mutex<Option<Child>>>;

pub fn spawn(request: AiRequest, tx: Sender<AiEvent>, slot: ChildSlot) {
    std::thread::spawn(move || {
        let purpose = request.purpose;
        if let Err(error) = run(request, &tx, &slot) {
            let _ = tx.send(AiEvent::Failed { purpose, error });
        }
        slot.lock().unwrap().take();
    });
}

fn command(request: &AiRequest) -> Command {
    let mut cmd = Command::new("claude");
    cmd.current_dir(&request.cwd)
        .args(["-p", &request.prompt, "--output-format", "stream-json", "--verbose"])
        .args(["--system-prompt", &request.system_prompt])
        .args(["--tools", "Read", "Grep", "Glob", "--allowedTools", "Read", "Grep", "Glob"])
        .args(["--strict-mcp-config", "--setting-sources", "", "--disable-slash-commands"]);
    for dir in &request.add_dirs {
        cmd.arg("--add-dir").arg(dir);
    }
    if let Some(session) = &request.resume {
        cmd.args(["--resume", session]);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

fn run(request: AiRequest, tx: &Sender<AiEvent>, slot: &ChildSlot) -> Result<(), String> {
    let mut child = command(&request)
        .spawn()
        .map_err(|e| format!("could not start `claude` ({e}); install Claude Code or sign in with `claude`"))?;
    let stdout = child.stdout.take().ok_or("no stdout from claude")?;
    let stderr = child.stderr.take();
    *slot.lock().unwrap() = Some(child);
    let mut final_event = None;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };
        match event.get("type").and_then(Value::as_str) {
            Some("assistant") => forward_tool_uses(&event, &request.cwd, tx),
            Some("result") => final_event = Some(event),
            _ => {}
        }
    }
    let status = slot.lock().unwrap().as_mut().and_then(|c| c.wait().ok());
    let Some(result) = final_event else {
        let mut err = String::new();
        if let Some(mut s) = stderr {
            use std::io::Read;
            let _ = s.read_to_string(&mut err);
        }
        return Err(match status {
            Some(s) if !s.success() && err.trim().is_empty() => "interrupted".into(),
            _ => format!("claude produced no result: {}", err.trim()),
        });
    };
    if result.get("is_error").and_then(Value::as_bool) == Some(true) {
        return Err(result.get("result").and_then(Value::as_str).unwrap_or("model error").to_string());
    }
    let _ = tx.send(AiEvent::Done {
        purpose: request.purpose,
        text: result.get("result").and_then(Value::as_str).unwrap_or_default().to_string(),
        session_id: result.get("session_id").and_then(Value::as_str).map(str::to_string),
        cost_usd: result.get("total_cost_usd").and_then(Value::as_f64).unwrap_or(0.0),
        duration_ms: result.get("duration_ms").and_then(Value::as_u64).unwrap_or(0),
    });
    Ok(())
}

/// `⎿ Read(src/app.rs)`-style lines for each tool call, paths made relative.
fn forward_tool_uses(event: &Value, cwd: &PathBuf, tx: &Sender<AiEvent>) {
    let Some(content) = event.pointer("/message/content").and_then(Value::as_array) else { return };
    for item in content.iter().filter(|c| c.get("type").and_then(Value::as_str) == Some("tool_use")) {
        let name = item.get("name").and_then(Value::as_str).unwrap_or("tool");
        let input = item.get("input").cloned().unwrap_or(Value::Null);
        let arg = ["file_path", "pattern", "path"]
            .iter()
            .find_map(|k| input.get(*k).and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let prefix = format!("{}/", cwd.display());
        let arg = arg.strip_prefix(&prefix).map(str::to_string).unwrap_or(arg);
        let _ = tx.send(AiEvent::Tool(format!("{name}({arg})")));
    }
}

pub fn interrupt(slot: &ChildSlot) -> bool {
    match slot.lock().unwrap().as_mut() {
        Some(child) => child.kill().is_ok(),
        None => false,
    }
}
