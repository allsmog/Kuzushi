use super::prelude::*;
use super::*;

pub(crate) fn content_length_value(line: &str) -> Option<usize> {
    let rest = line
        .strip_prefix("Content-Length:")
        .or_else(|| line.strip_prefix("content-length:"))?;
    rest.trim().parse().ok()
}

pub(crate) async fn read_json_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    len: usize,
) -> Result<Value> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub(crate) async fn read_until_crlf<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut Vec<u8>,
) -> Result<usize> {
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(buf.len());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            return Ok(buf.len());
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspLocation {
    pub(crate) uri: String,
    pub(crate) range: LspRange,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspRange {
    pub(crate) start: LspPosition,
    #[allow(dead_code)]
    pub(crate) end: LspPosition,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspPosition {
    pub(crate) line: u32,
    pub(crate) character: u32,
}

pub fn parse_locations(value: &Value) -> Vec<(String, u32, u32)> {
    fn one(loc: &LspLocation) -> Option<(String, u32, u32)> {
        let path = loc
            .uri
            .strip_prefix("file://")
            .unwrap_or(&loc.uri)
            .to_string();
        // LSP positions are 0-based; Kuzushi schema is 1-based.
        Some((
            path,
            loc.range.start.line + 1,
            loc.range.start.character + 1,
        ))
    }

    if value.is_null() {
        return Vec::new();
    }
    if let Ok(single) = serde_json::from_value::<LspLocation>(value.clone()) {
        return one(&single).into_iter().collect();
    }
    if let Ok(many) = serde_json::from_value::<Vec<LspLocation>>(value.clone()) {
        return many.iter().filter_map(one).collect();
    }
    Vec::new()
}
