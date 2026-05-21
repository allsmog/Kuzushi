use serde::de::DeserializeOwned;

pub(crate) fn next_jsonl_number<T>(
    body: &str,
    number: impl Fn(&T) -> usize,
) -> usize
where
    T: DeserializeOwned,
{
    let mut occupied_rows = 0usize;
    let mut max_number = 0usize;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        occupied_rows += 1;
        if let Ok(value) = serde_json::from_str::<T>(line) {
            max_number = max_number.max(number(&value));
        }
    }
    max_number.max(occupied_rows).saturating_add(1)
}
