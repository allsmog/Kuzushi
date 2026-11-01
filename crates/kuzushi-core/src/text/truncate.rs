//! One byte-budget truncation policy for every surface that clips text to a
//! byte limit.
//!
//! `&text[..limit]` panics with "byte index N is not a char boundary" when the
//! limit lands inside a multi-byte character. The text these call sites clip is
//! scanned repository source, build manifests, git output, model replies and
//! operator configuration, where non-ASCII is ordinary rather than hostile: a
//! CJK comment, an accented author name, or an emoji in a string literal is
//! enough. Several call sites had each written their own boundary walk and
//! three had written none, so those three turned such a file into a crash.
//! The policy lives here once.

/// The largest index at or below `index` that `text` can be split at.
///
/// Mirrors the still-unstable `str::floor_char_boundary`. An `index` past the
/// end clamps to `text.len()`, and index 0 is always a boundary, so the walk
/// always terminates.
pub fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut end = index.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// The longest prefix of `text` that fits within `max_bytes`, cut at a
/// character boundary.
///
/// Callers append their own truncation marker: the wording is operator-facing
/// copy that differs per surface, while where to cut is the policy.
pub fn utf8_prefix(text: &str, max_bytes: usize) -> &str {
    &text[..floor_char_boundary(text, max_bytes)]
}

#[cfg(test)]
mod tests {
    use super::{floor_char_boundary, utf8_prefix};

    #[test]
    fn ascii_text_is_cut_at_the_requested_byte() {
        assert_eq!(floor_char_boundary("abcdef", 4), 4);
        assert_eq!(utf8_prefix("abcdef", 4), "abcd");
    }

    #[test]
    fn a_limit_inside_a_multi_byte_character_walks_back_to_its_start() {
        // "é" is two bytes, so byte 1 is a continuation byte.
        assert_eq!(floor_char_boundary("aé", 2), 1);
        assert_eq!(utf8_prefix("aé", 2), "a");
        // "🔒" is four bytes; every interior offset falls back to its start.
        let locked = "ab🔒";
        for limit in 3..=5 {
            assert_eq!(floor_char_boundary(locked, limit), 2);
            assert_eq!(utf8_prefix(locked, limit), "ab");
        }
        assert_eq!(utf8_prefix(locked, 6), locked);
    }

    #[test]
    fn a_limit_at_or_past_the_end_keeps_the_whole_string() {
        assert_eq!(floor_char_boundary("héllo", 32), "héllo".len());
        assert_eq!(utf8_prefix("héllo", 32), "héllo");
        assert_eq!(utf8_prefix("", 8), "");
    }

    #[test]
    fn a_zero_limit_keeps_nothing_rather_than_panicking() {
        assert_eq!(floor_char_boundary("日本語", 0), 0);
        assert_eq!(utf8_prefix("日本語", 0), "");
    }

    #[test]
    fn every_limit_over_a_mixed_width_string_yields_a_valid_prefix() {
        let mixed = "a é 日 🔒 z";
        for limit in 0..=mixed.len() + 4 {
            let prefix = utf8_prefix(mixed, limit);
            assert!(mixed.starts_with(prefix));
            assert!(prefix.len() <= limit.min(mixed.len()));
        }
    }
}
