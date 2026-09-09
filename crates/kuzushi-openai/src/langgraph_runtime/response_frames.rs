use super::response_text::{ResponseTextEvent, ResponseTextObserver};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Reset,
    Text { text: String },
    Result { result: serde_json::Value },
}

#[derive(Default)]
struct FrameState {
    started: bool,
    result: Option<Vec<u8>>,
}

/// Only the terminal result reaches the existing typed bridge decoder.
/// Legacy single-JSON adapters remain valid and emit no preview events.
pub(super) fn read_response_frames(
    reader: &mut impl Read,
    limit: usize,
    observer: &ResponseTextObserver,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(reader.take(limit.saturating_add(1) as u64));
    let mut total = 0;
    let first = read_line(&mut reader, &mut total, limit)?;
    if !first.starts_with(&[0x1e]) {
        return read_legacy_response(reader, first, limit);
    }
    let mut state = FrameState::default();
    state.accept(&first, observer)?;
    loop {
        let line = read_line(&mut reader, &mut total, limit)?;
        if line.is_empty() {
            break;
        }
        state.accept(&line, observer)?;
    }
    state
        .result
        .context("LangGraph response stream ended without a terminal result")
}

fn read_line(reader: &mut impl BufRead, total: &mut usize, limit: usize) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    *total += reader
        .read_until(b'\n', &mut line)
        .context("could not read LangGraph response stream")?;
    ensure!(
        *total <= limit,
        "LangGraph response stream exceeded capture limit"
    );
    Ok(line)
}

fn read_legacy_response(
    mut reader: impl Read,
    mut bytes: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>> {
    reader
        .read_to_end(&mut bytes)
        .context("could not read LangGraph response")?;
    ensure!(
        bytes.len() <= limit,
        "LangGraph response exceeded capture limit"
    );
    Ok(bytes)
}

impl FrameState {
    fn accept(&mut self, line: &[u8], observer: &ResponseTextObserver) -> Result<()> {
        ensure!(
            self.result.is_none(),
            "LangGraph response stream continued after its terminal result"
        );
        ensure!(
            line.first() == Some(&0x1e) && line.last() == Some(&b'\n'),
            "invalid LangGraph response frame boundary"
        );
        let frame: Frame = serde_json::from_slice(&line[1..])
            .map_err(|_| anyhow::anyhow!("invalid LangGraph response frame"))?;
        self.apply(frame, observer)
    }

    fn apply(&mut self, frame: Frame, observer: &ResponseTextObserver) -> Result<()> {
        match frame {
            Frame::Reset => {
                self.started = true;
                observer.emit(ResponseTextEvent::Reset);
            }
            Frame::Text { text } => self.emit_text(text, observer)?,
            Frame::Result { result } => {
                ensure!(result.is_object(), "invalid LangGraph terminal result");
                self.result = Some(serde_json::to_vec(&result)?);
            }
        }
        Ok(())
    }

    fn emit_text(&self, text: String, observer: &ResponseTextObserver) -> Result<()> {
        ensure!(self.started, "LangGraph text arrived before response start");
        ensure!(
            text.len() <= 64 * 1024,
            "LangGraph text frame exceeded capture limit"
        );
        observer.emit(ResponseTextEvent::Delta(text));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
