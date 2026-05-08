use super::prelude::*;
use super::*;

pub(crate) fn wait_for_process(
    tool_name: &str,
    child: &mut Child,
    process_group_id: Option<u32>,
    cancel: &ScanCancellation,
) -> Result<Option<ExitStatus>> {
    loop {
        if cancel.is_cancelled() {
            kill_child(child, process_group_id);
            let _ = child.wait();
            return Ok(None);
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{tool_name}: could not poll subprocess"))?
        {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(75));
    }
}

pub(crate) fn kill_child(child: &mut Child, process_group_id: Option<u32>) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            return;
        }
    }
    let _ = child.kill();
}

pub(crate) fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

pub(crate) fn read_pipe(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub(crate) fn required_string(input: &Value, key: &str, message: &str) -> Result<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

pub(crate) fn optional_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(value) => {
                    Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
                }
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a string"),
            };
        }
    }
    Ok(None)
}

pub(crate) fn optional_u64(input: &Value, keys: &[&str]) -> Result<Option<u64>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::Number(number) => number
                    .as_u64()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::String(value) => value
                    .parse::<u64>()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a non-negative integer"),
            };
        }
    }
    Ok(None)
}

pub(crate) fn normalize_subdomain(candidate: &str, domain: &str) -> Option<String> {
    let host = candidate
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == domain || !host.ends_with(&format!(".{domain}")) {
        return None;
    }
    Some(host)
}
