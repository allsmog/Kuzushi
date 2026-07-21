//! Source-location extraction from ASAN/libFuzzer crash logs.
//!
//! Sanitizer frames look like `#N 0xADDR in func /abs/path/file.cpp:LINE:COL`.
//! The decisive frame is the first one in application code — not the
//! sanitizer runtime, not the interceptors, not the fuzz harness itself —
//! preferring frames under the scanned source root so the finding lands on
//! repository code the reviewer can open.

/// Extract `(file, line)` from a crash log. Frames under `source_hint` win;
/// otherwise the first non-runtime frame is used. Paths under the hint are
/// returned repo-relative.
pub fn source_location(crash_output: &str, source_hint: &str) -> Option<(String, u32)> {
    let frames: Vec<(String, u32)> = crash_output
        .lines()
        .filter_map(parse_frame_line)
        .filter(|(file, _)| !is_runtime_frame(file))
        .collect();
    let preferred = frames
        .iter()
        .find(|(file, _)| !source_hint.is_empty() && file.starts_with(source_hint));
    let (file, line) = preferred.or_else(|| frames.first())?;
    Some((relativize(file, source_hint), *line))
}

fn relativize(file: &str, source_hint: &str) -> String {
    file.strip_prefix(source_hint)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .filter(|rest| !rest.is_empty())
        .unwrap_or_else(|| file.to_string())
}

/// Parse one `#N 0x... in <func> <file>:<line>[:<col>]` frame line. Frames
/// without symbolized file info (`(module+0x...)`) yield None.
fn parse_frame_line(line: &str) -> Option<(String, u32)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('#') {
        return None;
    }
    let location = trimmed.split_whitespace().last()?;
    if location.starts_with('(') {
        return None;
    }
    split_file_line(location)
}

/// Split `file:line[:col]`, tolerating drive-less absolute paths and a
/// trailing column suffix.
fn split_file_line(location: &str) -> Option<(String, u32)> {
    let mut parts = location.rsplitn(3, ':');
    let last = parts.next()?;
    let middle = parts.next()?;
    if let Ok(line) = middle.parse::<u32>() {
        // file:line:col — the middle segment is the line number.
        let file = parts.next()?;
        last.parse::<u32>().ok()?;
        return Some((file.to_string(), line));
    }
    // file:line — the last segment is the line number.
    let line = last.parse::<u32>().ok()?;
    let file = match parts.next() {
        Some(head) => format!("{head}:{middle}"),
        None => middle.to_string(),
    };
    Some((file, line))
}

fn is_runtime_frame(file: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    lower.contains("sanitizer")
        || lower.contains("compiler-rt")
        || lower.contains("libfuzzer")
        || lower.contains("asan_")
        || lower.contains("interceptor")
        || lower.ends_with("harness.cpp")
        || lower.starts_with("/usr/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRASH: &str = "==12==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60\n\
        READ of size 8 at 0x60 thread T0\n\
        #0 0x55e1 in __asan_memcpy /build/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3\n\
        #1 0x55e2 in ns::Parse(unsigned char const*, unsigned long) /repo/src/cpp/code/vhdx/parser.cpp:108:11\n\
        #2 0x55e3 in LLVMFuzzerTestOneInput /ws/targets/c/vhdx/harness.cpp:31:5\n\
        #3 0x55e4 in main (/ws/bin/vhdx/fuzzer+0x1234)\n";

    #[test]
    fn first_application_frame_under_the_source_root_wins_and_is_relativized() {
        let (file, line) = source_location(CRASH, "/repo").unwrap();
        assert_eq!(file, "src/cpp/code/vhdx/parser.cpp");
        assert_eq!(line, 108);
    }

    #[test]
    fn without_a_matching_hint_the_first_non_runtime_frame_is_used_absolute() {
        let (file, line) = source_location(CRASH, "/elsewhere").unwrap();
        assert_eq!(file, "/repo/src/cpp/code/vhdx/parser.cpp");
        assert_eq!(line, 108);
    }

    #[test]
    fn runtime_only_or_unsymbolized_logs_yield_none() {
        let runtime_only = "#0 0x1 in __asan_memcpy /rt/asan/asan_interceptors.cpp:22\n\
                            #1 0x2 in main (/bin/fuzzer+0x1)\n";
        assert!(source_location(runtime_only, "/repo").is_none());
        assert!(source_location("INFO: Seed: 1089322086\n", "/repo").is_none());
    }

    #[test]
    fn frame_without_column_suffix_parses() {
        let log = "#1 0x2 in f /repo/a.cpp:42\n";
        assert_eq!(
            source_location(log, "/repo").unwrap(),
            ("a.cpp".to_string(), 42)
        );
    }
}
