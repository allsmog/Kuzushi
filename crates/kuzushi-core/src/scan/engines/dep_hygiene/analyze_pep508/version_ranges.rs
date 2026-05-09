pub(in crate::scan::engines::dep_hygiene) fn is_floor_only_number_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') {
        return false;
    }
    let Some(rest) = value.strip_prefix('>') else {
        return false;
    };
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    rest.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

pub(in crate::scan::engines::dep_hygiene) fn is_floor_only_nonempty_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') || value.split_whitespace().count() != 1 {
        return false;
    }
    is_floor_only_number_range(value)
}

pub(in crate::scan::engines::dep_hygiene) fn is_go_pseudo_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("v0.0.0-") else {
        return false;
    };
    let Some((timestamp, hash)) = rest.split_once('-') else {
        return false;
    };
    timestamp.len() == 14
        && timestamp.chars().all(|ch| ch.is_ascii_digit())
        && hash.len() == 12
        && hash.chars().all(|ch| ch.is_ascii_hexdigit())
}
