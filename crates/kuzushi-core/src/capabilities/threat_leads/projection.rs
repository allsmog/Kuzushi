use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

pub(super) type Elements<'a> = BTreeMap<&'a str, &'a Value>;
const MAX_ELEMENTS: usize = 2048;
const MAX_REFERENCES: usize = 32;
const MAX_ID_BYTES: usize = 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_CARD_BYTES: usize = 128 * 1024;
const MAX_CARDS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Projection {
    omitted_elements: usize,
    duplicate_element_ids: usize,
    omitted_values: usize,
    duplicate_references: usize,
    truncated_text_fields: usize,
    omitted_lead_cards: usize,
    retained_card_bytes: usize,
}

impl Projection {
    pub(super) fn elements<'a>(&mut self, rows: Option<&'a Vec<Value>>) -> Elements<'a> {
        let rows = rows.map(Vec::as_slice).unwrap_or_default();
        self.omitted_elements += rows.len().saturating_sub(MAX_ELEMENTS);
        let mut elements = Elements::new();
        for row in rows.iter().take(MAX_ELEMENTS) {
            if let Some(id) = self.identity_ref(row.get("id").unwrap_or(&Value::Null)) {
                self.duplicate_element_ids += usize::from(elements.insert(id, row).is_some());
            } else {
                self.omitted_elements += 1;
            }
        }
        elements
    }

    pub(super) fn text(&mut self, value: &Value, key: &str) -> Option<String> {
        let text = value.get(key)?.as_str()?.trim();
        if text.is_empty() {
            return None;
        }
        let mut end = text.len().min(MAX_TEXT_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.truncated_text_fields += usize::from(end < text.len());
        Some(text[..end].to_string())
    }

    pub(super) fn identity(&mut self, value: &Value, key: &str) -> Option<String> {
        self.identity_ref(value.get(key)?).map(str::to_string)
    }

    fn identity_ref<'a>(&mut self, value: &'a Value) -> Option<&'a str> {
        let text = value.as_str()?.trim();
        if text.is_empty() || text.len() > MAX_ID_BYTES {
            self.omitted_values += 1;
            return None;
        }
        Some(text)
    }

    pub(super) fn references(&mut self, value: &Value, key: &str) -> Vec<String> {
        let Some(rows) = value.get(key).and_then(Value::as_array) else {
            return Vec::new();
        };
        self.omitted_values += rows.len().saturating_sub(MAX_REFERENCES);
        let mut unique = BTreeSet::new();
        let mut result = Vec::new();
        for row in rows.iter().take(MAX_REFERENCES) {
            if let Some(id) = self.identity_ref(row) {
                self.retain_reference(id, &mut unique, &mut result);
            }
        }
        result
    }

    fn retain_reference(
        &mut self,
        id: &str,
        unique: &mut BTreeSet<String>,
        result: &mut Vec<String>,
    ) {
        if unique.insert(id.into()) {
            result.push(id.into());
        } else {
            self.duplicate_references += 1;
        }
    }

    pub(super) fn admit(&mut self, card: &Value) -> bool {
        let limit = MAX_CARD_BYTES.min(MAX_CARDS_BYTES - self.retained_card_bytes);
        let mut counter = ByteCounter { bytes: 0, limit };
        if serde_json::to_writer_pretty(&mut counter, card).is_err() {
            self.omitted_lead_cards += 1;
            return false;
        }
        self.retained_card_bytes += counter.bytes;
        true
    }

    pub(super) fn is_partial(&self) -> bool {
        [
            self.omitted_elements,
            self.duplicate_element_ids,
            self.omitted_values,
            self.truncated_text_fields,
            self.omitted_lead_cards,
        ]
        .into_iter()
        .any(|count| count > 0)
    }

    pub(super) fn receipt(&self) -> Value {
        let mut value = json!(self);
        value["schemaVersion"] = json!(1);
        value["maxDfdRowsPerKind"] = json!(MAX_ELEMENTS);
        value["maxReferencesPerField"] = json!(MAX_REFERENCES);
        value["maxIdentityBytes"] = json!(MAX_ID_BYTES);
        value["maxTextFieldBytes"] = json!(MAX_TEXT_BYTES);
        value["maxCardBytes"] = json!(MAX_CARD_BYTES);
        value["maxRetainedCardBytes"] = json!(MAX_CARDS_BYTES);
        value
    }
}

struct ByteCounter {
    bytes: usize,
    limit: usize,
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes) {
            return Err(io::Error::other("threat lead card capacity reached"));
        }
        self.bytes += buffer.len();
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
