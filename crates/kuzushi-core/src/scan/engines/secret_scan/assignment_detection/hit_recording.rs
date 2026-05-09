use super::*;

pub(crate) fn push_hit(
    hits: &mut Vec<SecretHit>,
    detector: Detector,
    matched: &str,
    captured_secret: &str,
    index: usize,
) {
    hits.push(SecretHit {
        detector,
        matched: matched.to_string(),
        captured_secret: captured_secret.to_string(),
        index,
    });
}
