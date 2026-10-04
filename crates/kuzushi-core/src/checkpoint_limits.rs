//! Shared bounded serialization and record decoding for resumable work.
use anyhow::{Context, Result};
use serde::de::{DeserializeOwned, Error, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use serde_json::value::RawValue;
use std::marker::PhantomData;

pub(crate) const MAX_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_RECORDS: usize = 512;

pub(crate) fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    kuzushi_mcp_common::server::bounded_json_bytes(value, limit)?
        .with_context(|| format!("checkpoint exceeds {limit} encoded bytes; resume unavailable"))
}

pub(crate) fn validate_record(value: &impl Serialize) -> Result<()> {
    encode(value, MAX_RECORD_BYTES).map(|_| ())
}

pub(crate) fn deserialize_records<'de, D, T, C>(deserializer: D) -> Result<C, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
    C: FromIterator<T>,
{
    deserializer.deserialize_seq(Records::<T, C>(PhantomData))
}

struct Records<T, C>(PhantomData<(T, C)>);

impl<'de, T: DeserializeOwned, C: FromIterator<T>> Visitor<'de> for Records<T, C> {
    type Value = C;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "at most {MAX_RECORDS} checkpoint records of {MAX_RECORD_BYTES} bytes"
        )
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<C, A::Error> {
        let mut records = Vec::new();
        while let Some(raw) = sequence.next_element::<&'de RawValue>()? {
            require_record_budget(raw, records.len()).map_err(A::Error::custom)?;
            records.push(serde_json::from_str::<T>(raw.get()).map_err(A::Error::custom)?);
        }
        Ok(records.into_iter().collect())
    }
}

fn require_record_budget(raw: &RawValue, count: usize) -> Result<()> {
    anyhow::ensure!(
        count < MAX_RECORDS,
        "checkpoint exceeds {MAX_RECORDS} records; resume unavailable"
    );
    anyhow::ensure!(
        raw.get().len() <= MAX_RECORD_BYTES,
        "checkpoint record exceeds {MAX_RECORD_BYTES} bytes; resume unavailable"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Deserialize)]
    struct Envelope {
        #[serde(deserialize_with = "decode")]
        records: Vec<Value>,
    }

    fn decode<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Value>, D::Error> {
        deserialize_records(deserializer)
    }

    #[test]
    fn checkpoint_record_count_is_enforced_while_decoding() {
        let allowed = format!("{{\"records\":[{}]}}", vec!["null"; MAX_RECORDS].join(","));
        assert_eq!(
            serde_json::from_str::<Envelope>(&allowed)
                .unwrap()
                .records
                .len(),
            MAX_RECORDS
        );
        let excessive = allowed.replace("]}", ",null]}");
        let error = serde_json::from_str::<Envelope>(&excessive).err().unwrap();
        assert!(error.to_string().contains("512 records"));
    }

    #[test]
    fn checkpoint_record_bytes_and_nested_values_are_rejected() {
        let excessive = format!("{{\"records\":[\"{}\"]}}", "x".repeat(MAX_RECORD_BYTES));
        let error = serde_json::from_str::<Envelope>(&excessive).err().unwrap();
        assert!(error.to_string().contains("record exceeds"));
        let nested = format!("{{\"records\":[{}0{}]}}", "[".repeat(200), "]".repeat(200));
        let error = serde_json::from_str::<Envelope>(&nested).err().unwrap();
        assert!(error.to_string().contains("recursion limit"));
    }

    #[test]
    fn checkpoint_serialization_stops_at_the_encoded_budget() {
        let value = "x".repeat(MAX_RECORD_BYTES);
        assert!(validate_record(&value).is_err());
        assert_eq!(encode(&"bounded", 9).unwrap(), b"\"bounded\"");
        assert!(encode(&"bounded", 8).is_err());
    }
}
