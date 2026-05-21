use super::*;

pub fn config_hash(config: &V2Config) -> Result<String> {
    let bytes = serde_json::to_vec(config).context("Could not serialize config for hashing")?;
    Ok(format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes)
    ))
}
