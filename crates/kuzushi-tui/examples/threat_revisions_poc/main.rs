//! TEMPORARY PoC — hotkey-driven threat-model generations, THREAT_MODEL.md
//! review/edit, and a Claude Code–style chat over the model.
//!
//! Plan: `~/.claude/plans/i-need-to-use-bubbly-zebra.md`. Not wired into the
//! shell; delete with the `threat-revisions-poc` feature.
//!
//!   ./try-threat-poc.sh [fixture|<repo>]
//!
//! Reads a real `.kuzushi/threat-models/` store with `--target`; new versions
//! and activation stay in memory. Chat and refine call a real model through
//! the local `claude` CLI; `e` opens THREAT_MODEL.md in $EDITOR (vim).

mod ai;
mod app;
mod chat;
mod md;
mod store;
mod ui;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Args {
    target: Option<PathBuf>,
    /// Headless: replay these inputs, print the final screen, exit.
    snapshot: Option<String>,
    size: (u16, u16),
    /// Write the demo revisions into a REAL store under this dir, then exit.
    seed: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut out = Args { target: None, snapshot: None, size: (140, 40), seed: None };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--target" => out.target = Some(PathBuf::from(args.next().context("--target needs a path")?)),
            "--demo" => out.target = None,
            "--snapshot" => out.snapshot = Some(args.next().context("--snapshot needs a key string")?),
            "--seed" => out.seed = Some(PathBuf::from(args.next().context("--seed needs a dir")?)),
            "--size" => {
                let v = args.next().context("--size needs WxH")?;
                let (w, h) = v.split_once('x').context("--size needs WxH")?;
                out.size = (w.parse()?, h.parse()?);
            }
            other => anyhow::bail!("unknown argument {other:?} (use --demo, --target <path>, --seed <dir>, --snapshot <keys>, --size WxH)"),
        }
    }
    Ok(out)
}

enum Input {
    Key(KeyEvent),
    Paste(String),
    /// Snapshot only: block until in-flight model work finishes.
    Wait,
}

/// `<Esc> <Enter> <Tab> <BackTab> <PgDn> <PgUp> <Up> <Down> <Left> <Right>
/// <Home> <End> <BS> <Del> <C-s> <C-x> <Paste:text>`, else literal chars.
fn parse_inputs(spec: &str) -> Vec<Input> {
    let mut out = Vec::new();
    let mut rest = spec;
    while let Some(c) = rest.chars().next() {
        if c == '<' {
            if let Some(end) = rest.find('>') {
                let token = &rest[1..end];
                if token == "Wait" {
                    out.push(Input::Wait);
                    rest = &rest[end + 1..];
                    continue;
                }
                if let Some(text) = token.strip_prefix("Paste:") {
                    out.push(Input::Paste(text.to_string()));
                    rest = &rest[end + 1..];
                    continue;
                }
                let key = match token {
                    "Esc" => Some(KeyCode::Esc),
                    "Enter" => Some(KeyCode::Enter),
                    "Tab" => Some(KeyCode::Tab),
                    "BackTab" => Some(KeyCode::BackTab),
                    "PgDn" => Some(KeyCode::PageDown),
                    "PgUp" => Some(KeyCode::PageUp),
                    "Up" => Some(KeyCode::Up),
                    "Down" => Some(KeyCode::Down),
                    "Left" => Some(KeyCode::Left),
                    "Right" => Some(KeyCode::Right),
                    "Home" => Some(KeyCode::Home),
                    "End" => Some(KeyCode::End),
                    "BS" => Some(KeyCode::Backspace),
                    "Del" => Some(KeyCode::Delete),
                    _ => None,
                }
                .map(|code| KeyEvent::new(code, KeyModifiers::NONE))
                .or_else(|| {
                    let ch = token.strip_prefix("C-")?.chars().next()?;
                    Some(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL))
                });
                if let Some(key) = key {
                    out.push(Input::Key(key));
                    rest = &rest[end + 1..];
                    continue;
                }
            }
        }
        out.push(Input::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
        rest = &rest[c.len_utf8()..];
    }
    out
}

fn snapshot(app: &mut app::App, keys: &str, (w, h): (u16, u16)) -> Result<()> {
    for input in parse_inputs(keys) {
        match input {
            Input::Key(key) => app.on_key(key),
            Input::Paste(text) => app.on_paste(text),
            Input::Wait => {
                let deadline = std::time::Instant::now() + Duration::from_secs(300);
                while app.busy.is_some() && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                    app.drain_ai();
                }
            }
        }
        if let Some(edit) = app.external_edit.take() {
            let result = run_editor(&edit.path);
            app.finish_edit(edit, result);
        }
        app.drain_ai();
    }
    if std::env::var_os("POC_DUMP_CHAT").is_some() {
        for msg in &app.chat {
            let (kind, text) = match msg {
                chat::Msg::User(t) => ("user", t),
                chat::Msg::Assistant(t) => ("assistant", t),
                chat::Msg::Tool(t) => ("tool", t),
                chat::Msg::Event(t) => ("event", t),
                chat::Msg::Error(t) => ("error", t),
            };
            eprintln!("[{kind}] {}", text.chars().take(300).collect::<String>().replace('\n', " ⏎ "));
        }
    }
    let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(w, h))?;
    terminal.draw(|f| ui::draw(f, app))?;
    let buffer = terminal.backend().buffer();
    for y in 0..h {
        let row: String = (0..w).map(|x| buffer[(x, y)].symbol().to_string()).collect();
        println!("{}", row.trim_end());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args()?;
    if let Some(dir) = &args.seed {
        return store::seed_real_store(dir);
    }
    let store = match &args.target {
        Some(root) => store::load_real(root)?,
        None => store::demo_store(),
    };
    let mut app = app::App::new(store);
    if let Some(keys) = &args.snapshot {
        return snapshot(&mut app, keys, args.size);
    }
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
        prev_hook(info);
    }));
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let result = run(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), DisableBracketedPaste, LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

fn run(terminal: &mut Term, app: &mut app::App) -> Result<()> {
    while !app.quit {
        app.drain_ai();
        terminal.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => app.on_key(key),
                Event::Paste(text) => app.on_paste(text),
                _ => {}
            }
        }
        if let Some(edit) = app.external_edit.take() {
            let result = with_suspended_tui(terminal, || run_editor(&edit.path))?;
            app.finish_edit(edit, result);
        }
    }
    Ok(())
}

/// Hand the terminal to a child program (vim) and take it back afterwards.
fn with_suspended_tui<T>(terminal: &mut Term, f: impl FnOnce() -> T) -> Result<T> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), DisableBracketedPaste, LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let out = f();
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen, EnableBracketedPaste)?;
    terminal.clear()?;
    Ok(out)
}

/// `$VISUAL` / `$EDITOR`, else vim. The value may carry arguments.
fn run_editor(path: &Path) -> std::result::Result<(), String> {
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).unwrap_or_else(|_| "vim".into());
    let mut parts = shlex_split(&editor);
    if parts.is_empty() {
        parts.push("vim".into());
    }
    let status = std::process::Command::new(&parts[0])
        .args(&parts[1..])
        .arg(path)
        .status()
        .map_err(|e| format!("could not start editor {editor:?}: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("editor {editor:?} exited with {status}; changes ignored")) }
}

fn shlex_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}
