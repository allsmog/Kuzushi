type Bindings = Vec<(String, String)>;

pub(super) fn applies(bindings: &[(String, String)]) -> bool {
    bindings.iter().any(|(_, label)| label == "study jobs")
}

pub(super) fn rows(bindings: Bindings) -> (Bindings, Bindings) {
    let (mut leave, mut reading): (Bindings, Bindings) = bindings
        .into_iter()
        .map(compact_binding)
        .partition(|(key, _)| matches!(key.as_str(), "Esc" | "Ctrl+C"));
    leave.sort_by_key(|(key, _)| u8::from(key != "Esc"));
    reading.sort_by_key(|(key, label)| reading_priority(key, label));
    (leave, reading)
}

pub(super) fn single_row(bindings: Bindings) -> Bindings {
    if !applies(&bindings) {
        return bindings;
    }
    let (leave, reading) = rows(bindings);
    leave.into_iter().chain(reading).collect()
}

fn reading_priority(key: &str, label: &str) -> u8 {
    if key == "PgUp/Dn" {
        return 0;
    }
    if label == "jobs" {
        return 1;
    }
    2
}

fn compact_binding((key, label): (String, String)) -> (String, String) {
    if label == "study jobs" {
        return (key, "jobs".into());
    }
    if key == "PgUp/PgDn" {
        return ("PgUp/Dn".into(), "read".into());
    }
    (key, label)
}

#[cfg(test)]
mod tests;
