use super::{ProcessBirthIdentity, ProcessObservation};
use std::path::Path;
use std::sync::OnceLock;

const MAX_PROC_STAT_BYTES: usize = 16 * 1024;
const MAX_BOOT_ID_BYTES: usize = 128;
static BOOT_ID: OnceLock<Option<String>> = OnceLock::new();

pub(super) fn observe(process_id: u32) -> ProcessObservation {
    if !Path::new("/proc").is_dir() {
        return ProcessObservation::Unknown;
    }
    let path = Path::new("/proc").join(process_id.to_string()).join("stat");
    let stat = match crate::bounded_file::read_utf8_text(&path, MAX_PROC_STAT_BYTES) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProcessObservation::Dead;
        }
        Err(_) => return ProcessObservation::Unknown,
    };
    observation_from_stat(&stat)
}

fn observation_from_stat(stat: &str) -> ProcessObservation {
    let Some((state, start_ticks)) = parse_stat_identity(stat) else {
        return ProcessObservation::Unknown;
    };
    if matches!(state, "Z" | "X" | "x") {
        return ProcessObservation::Dead;
    }
    let Some(boot_id) = boot_id() else {
        return ProcessObservation::Alive(None);
    };
    ProcessObservation::Alive(Some(ProcessBirthIdentity {
        platform: "linux".to_string(),
        boot_id: Some(boot_id),
        start_token: start_ticks.to_string(),
    }))
}

fn parse_stat_identity(stat: &str) -> Option<(&str, u64)> {
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let state = *fields.first()?;
    let start_ticks = fields.get(19)?.parse().ok()?;
    Some((state, start_ticks))
}

fn boot_id() -> Option<String> {
    BOOT_ID
        .get_or_init(|| {
            crate::bounded_file::read_utf8_text(
                Path::new("/proc/sys/kernel/random/boot_id"),
                MAX_BOOT_ID_BYTES,
            )
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_start_ticks_after_a_command_containing_parentheses() {
        let mut suffix = vec!["S".to_string()];
        suffix.extend((4..=21).map(|field| field.to_string()));
        suffix.push("987654".to_string());
        let stat = format!("123 (worker ) name) {}", suffix.join(" "));

        assert_eq!(parse_stat_identity(&stat), Some(("S", 987654)));
    }

    #[test]
    fn zombie_state_is_dead() {
        let mut suffix = vec!["Z".to_string()];
        suffix.extend((4..=21).map(|field| field.to_string()));
        suffix.push("1".to_string());

        assert_eq!(
            observation_from_stat(&format!("7 (done) {}", suffix.join(" "))),
            ProcessObservation::Dead
        );
    }
}
