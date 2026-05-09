use super::*;

pub(in crate::scan::engines::secret_scan) fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::<char, usize>::new();
    for ch in input.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let len = input.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub(in crate::scan::engines::secret_scan) fn redact_secret(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let prefix = chars.iter().take(4).collect::<String>();
    format!("{}{}", prefix, "*".repeat((chars.len() - 4).min(8)))
}

pub(in crate::scan::engines::secret_scan) fn fingerprint_for(
    repo_root: &Path,
    detector_id: &str,
    file_path: &str,
    line: u32,
    matched: &str,
) -> String {
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let input = format!("{repo_name}|secret-scan|{detector_id}|{file_path}|{line}|{matched}");
    format!(
        "secret-scan:{detector_id}:{:016x}",
        fnv1a64(input.as_bytes())
    )
}

pub(in crate::scan::engines::secret_scan) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
