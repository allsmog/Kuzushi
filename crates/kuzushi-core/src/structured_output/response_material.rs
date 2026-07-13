use super::*;
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use std::io::Write;

pub(crate) const MAX_STRUCTURED_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const OMITTED_SEPARATOR: &str = "\n... [bytes omitted] ...\n";

#[derive(Debug, Clone)]
pub(super) struct ByteEvidence {
    bytes: usize,
    sha256: String,
    head: Vec<u8>,
    tail: Vec<u8>,
}

impl ByteEvidence {
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        let mut writer = EvidenceWriter::default();
        writer
            .write_all(bytes)
            .expect("evidence writer cannot fail");
        writer.finish()
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn digest(&self) -> &str {
        &self.sha256
    }

    pub(super) fn render(&self, label: &str, limit: usize) -> String {
        if self.bytes <= limit && self.bytes == self.head.len() {
            return safe_utf8_head(&self.head, self.bytes).to_string();
        }
        let header = format!(
            "[{label} excerpt; original_bytes={}; sha256={}]\n",
            self.bytes, self.sha256
        );
        if header.len() >= limit {
            return safe_utf8_head(header.as_bytes(), limit).to_string();
        }
        let excerpt_budget = limit - header.len();
        let separator_bytes = OMITTED_SEPARATOR.len().min(excerpt_budget);
        let content_budget = excerpt_budget.saturating_sub(separator_bytes);
        let head_budget = content_budget / 2;
        let tail_budget = content_budget.saturating_sub(head_budget);
        format!(
            "{header}{head}{separator}{tail}",
            head = safe_utf8_head(&self.head, head_budget),
            separator = &OMITTED_SEPARATOR[..separator_bytes],
            tail = safe_utf8_tail(&self.tail, tail_budget),
        )
    }
}

#[derive(Debug, Clone)]
pub(super) struct ResponseMaterial {
    text: ByteEvidence,
    structured: Option<ByteEvidence>,
    total_bytes: usize,
}

impl ResponseMaterial {
    pub(super) fn from_response(response: &AgentQueryResponse) -> Result<Self> {
        let text = ByteEvidence::from_bytes(response.text.as_bytes());
        let structured = response
            .structured
            .as_ref()
            .map(serialized_value_evidence)
            .transpose()?;
        let total_bytes = text
            .bytes()
            .checked_add(structured.as_ref().map_or(0, ByteEvidence::bytes))
            .context("structured response byte count overflowed")?;
        Ok(Self {
            text,
            structured,
            total_bytes,
        })
    }

    pub(super) fn ensure_within_budget(&self) -> Result<()> {
        if self.total_bytes <= MAX_STRUCTURED_RESPONSE_BYTES {
            return Ok(());
        }
        anyhow::bail!(self.oversize_message())
    }

    pub(super) fn render(&self, limit: usize) -> String {
        let Some(structured) = &self.structured else {
            return self.text.render("model text", limit);
        };
        const SCAFFOLD: &str = "structured:\n\n\ntext:\n";
        let component_budget = limit.saturating_sub(SCAFFOLD.len()) / 2;
        format!(
            "structured:\n{}\n\ntext:\n{}",
            structured.render("structured JSON", component_budget),
            self.text.render("model text", component_budget),
        )
    }

    fn oversize_message(&self) -> String {
        let structured = self.structured.as_ref().map_or_else(
            || "none".to_string(),
            |value| format!("{} bytes sha256={}", value.bytes(), value.digest()),
        );
        format!(
            "model response material is {total} bytes; limit is {limit} bytes; text={text_bytes} bytes sha256={text_digest}; structured={structured}",
            total = self.total_bytes,
            limit = MAX_STRUCTURED_RESPONSE_BYTES,
            text_bytes = self.text.bytes(),
            text_digest = self.text.digest(),
        )
    }
}

pub(crate) fn ensure_response_material_budget(response: &AgentQueryResponse) -> Result<()> {
    ResponseMaterial::from_response(response)?.ensure_within_budget()
}

pub(super) fn ensure_text_parse_budget(text: &str) -> Result<()> {
    if text.len() <= MAX_STRUCTURED_RESPONSE_BYTES {
        return Ok(());
    }
    let evidence = ByteEvidence::from_bytes(text.as_bytes());
    anyhow::bail!(
        "model response text is {} bytes; limit is {} bytes; sha256={}",
        evidence.bytes(),
        MAX_STRUCTURED_RESPONSE_BYTES,
        evidence.digest(),
    )
}

pub(super) fn serialized_value_evidence(value: &Value) -> Result<ByteEvidence> {
    let mut writer = EvidenceWriter::default();
    serde_json::to_writer(&mut writer, value).context("Could not measure structured JSON")?;
    Ok(writer.finish())
}

pub(super) fn formatted_evidence(arguments: std::fmt::Arguments<'_>) -> Result<ByteEvidence> {
    let mut writer = EvidenceWriter::default();
    std::fmt::write(&mut writer, arguments)
        .map_err(|_| anyhow::anyhow!("Could not format evidence"))?;
    Ok(writer.finish())
}

struct EvidenceWriter {
    bytes: usize,
    hasher: Sha256,
    head: Vec<u8>,
    tail: VecDeque<u8>,
}

impl Default for EvidenceWriter {
    fn default() -> Self {
        Self {
            bytes: 0,
            hasher: Sha256::new(),
            head: Vec::with_capacity(MAX_CAPTURE_BYTES),
            tail: VecDeque::with_capacity(MAX_CAPTURE_BYTES),
        }
    }
}

impl EvidenceWriter {
    fn finish(self) -> ByteEvidence {
        ByteEvidence {
            bytes: self.bytes,
            sha256: digest_hex(self.hasher.finalize()),
            head: self.head,
            tail: self.tail.into_iter().collect(),
        }
    }

    fn capture_head(&mut self, bytes: &[u8]) {
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(self.head.len());
        self.head
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }

    fn capture_tail(&mut self, bytes: &[u8]) {
        if bytes.len() >= MAX_CAPTURE_BYTES {
            self.tail.clear();
            self.tail
                .extend(bytes[bytes.len() - MAX_CAPTURE_BYTES..].iter().copied());
            return;
        }
        let overflow = self
            .tail
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(MAX_CAPTURE_BYTES);
        self.tail.drain(..overflow);
        self.tail.extend(bytes.iter().copied());
    }
}

impl Write for EvidenceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(|| {
            std::io::Error::other("structured response byte count overflowed usize")
        })?;
        self.hasher.update(bytes);
        self.capture_head(bytes);
        self.capture_tail(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Write for EvidenceWriter {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.write_all(value.as_bytes())
            .map_err(|_| std::fmt::Error)
    }
}

fn safe_utf8_head(bytes: &[u8], limit: usize) -> &str {
    let mut end = bytes.len().min(limit);
    while std::str::from_utf8(&bytes[..end]).is_err() {
        end = end.saturating_sub(1);
    }
    std::str::from_utf8(&bytes[..end]).expect("trimmed UTF-8 head")
}

fn safe_utf8_tail(bytes: &[u8], limit: usize) -> &str {
    let start = bytes.len().saturating_sub(limit);
    let offset = (start..bytes.len())
        .find(|index| std::str::from_utf8(&bytes[*index..]).is_ok())
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[offset..]).expect("trimmed UTF-8 tail")
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn payload_larger_than_capture_never_masquerades_as_complete() {
        let payload = "x".repeat(MAX_CAPTURE_BYTES * 2);
        let evidence = ByteEvidence::from_bytes(payload.as_bytes());

        let rendered = evidence.render("payload", MAX_CAPTURE_BYTES * 4);

        assert!(rendered.contains("payload excerpt"), "{rendered}");
        assert!(rendered.contains("original_bytes=32768"), "{rendered}");
        assert!(rendered.contains("bytes omitted"), "{rendered}");
        assert!(rendered.contains(evidence.digest()), "{rendered}");
        assert_ne!(rendered, payload);
    }

    #[test]
    fn evidence_excerpt_is_utf8_safe_and_bounded() {
        let payload = format!("start-{}-end", "é".repeat(MAX_CAPTURE_BYTES));
        let evidence = ByteEvidence::from_bytes(payload.as_bytes());

        let rendered = evidence.render("unicode", 257);

        assert!(rendered.len() <= 257);
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
        assert!(rendered.contains(&payload[..6]));
        assert!(rendered.ends_with("-end"));
    }

    #[test]
    fn response_material_limit_is_inclusive_and_digest_is_exact() {
        let at_limit = AgentQueryResponse {
            text: "x".repeat(MAX_STRUCTURED_RESPONSE_BYTES),
            ..Default::default()
        };
        ResponseMaterial::from_response(&at_limit)
            .unwrap()
            .ensure_within_budget()
            .unwrap();

        let over = AgentQueryResponse {
            text: "x".repeat(MAX_STRUCTURED_RESPONSE_BYTES + 1),
            ..Default::default()
        };
        let material = ResponseMaterial::from_response(&over).unwrap();
        let error = material.ensure_within_budget().unwrap_err().to_string();
        let digest = kuzushi_mcp_common::cache::sha256_hex_bytes(over.text.as_bytes());

        assert!(error.contains(&(MAX_STRUCTURED_RESPONSE_BYTES + 1).to_string()));
        assert!(error.contains(&MAX_STRUCTURED_RESPONSE_BYTES.to_string()));
        assert!(error.contains(&digest));
    }

    #[test]
    fn structured_value_is_counted_and_hashed_without_a_pretty_copy() {
        let value = json!({"payload": "é".repeat(20_000)});
        let serialized = serde_json::to_vec(&value).unwrap();

        let evidence = serialized_value_evidence(&value).unwrap();

        assert_eq!(evidence.bytes(), serialized.len());
        assert_eq!(
            evidence.digest(),
            kuzushi_mcp_common::cache::sha256_hex_bytes(&serialized)
        );
    }
}
