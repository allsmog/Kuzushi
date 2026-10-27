//! Select filename examples from saved membership without reading source again.
use super::*;
use std::collections::{BTreeSet, VecDeque};

const MAX_NAMES: usize = 512;
const MAX_BYTES: usize = 16_384;
const BALANCED: &str = "root-balanced-v1";

pub(super) fn validate(value: Option<&Value>) -> Result<()> {
    match value {
        None => Ok(()),
        Some(Value::String(value)) if matches!(value.as_str(), "prefix-v1" | BALANCED) => Ok(()),
        _ => anyhow::bail!("fileSelection must be prefix-v1 or root-balanced-v1"),
    }
}

pub(super) fn sample(files: &[String], selection: Option<&Value>) -> Result<Value> {
    validate(selection)?;
    if selection.and_then(Value::as_str) != Some(BALANCED) {
        return super::sample(files, MAX_NAMES, MAX_BYTES);
    }
    let ordered = ordered_files(files);
    let mut sample = sample_candidates(ordered, files.len(), MAX_NAMES, MAX_BYTES - 2)?;
    sample["selection"] = json!(BALANCED);
    append_coverage(&mut sample, files);
    Ok(sample)
}

fn ordered_files(files: &[String]) -> Vec<&str> {
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for file in files {
        groups.entry(group(file)).or_default().push(file);
    }
    for paths in groups.values_mut() {
        paths.sort_unstable();
    }
    let mut ordered = groups.remove("").unwrap_or_default();
    let mut queues: Vec<VecDeque<_>> = groups.into_values().map(VecDeque::from).collect();
    while !queues.is_empty() {
        ordered.extend(queues.iter_mut().filter_map(VecDeque::pop_front));
        queues.retain(|queue| !queue.is_empty());
    }
    ordered
}

/// The same two-level grouping feeds directory counts and filename balancing.
pub(super) fn group(file: &str) -> &str {
    let Some(first) = file.find('/') else {
        return "";
    };
    let end = file[first + 1..]
        .find('/')
        .map_or(first, |offset| first + 1 + offset);
    &file[..end]
}

fn append_coverage(sample: &mut Value, files: &[String]) {
    let supplied: Vec<_> = sample["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    let roots = root_count(files.iter().map(String::as_str));
    let supplied_roots = root_count(supplied.iter().copied());
    let groups = group_count(files.iter().map(String::as_str));
    let supplied_groups = group_count(supplied.iter().copied());
    sample["rootFiles"] = json!({"total":roots,"supplied":supplied_roots});
    sample["directoryGroups"] = json!({"total":groups,"supplied":supplied_groups});
}

fn root_count<'a>(files: impl Iterator<Item = &'a str>) -> usize {
    files.filter(|file| group(file).is_empty()).count()
}

fn group_count<'a>(files: impl Iterator<Item = &'a str>) -> usize {
    files
        .map(group)
        .filter(|group| !group.is_empty())
        .collect::<BTreeSet<_>>()
        .len()
}

pub(super) fn summary(sample: &Value) -> Option<String> {
    (sample["selection"] == BALANCED).then(|| format!(
        "Filename sample: root files first, balanced directory groups; root names {}/{}, directory groups {}/{}. Unlisted names remain in inventory and coverage review.",
        sample["rootFiles"]["supplied"], sample["rootFiles"]["total"],
        sample["directoryGroups"]["supplied"], sample["directoryGroups"]["total"]))
}

#[cfg(test)]
mod tests;
