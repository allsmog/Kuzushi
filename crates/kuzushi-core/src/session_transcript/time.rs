use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now_timestamp() -> String {
    timestamp_from_millis(now_unix_millis())
}

pub(super) fn date_path_components() -> (String, String, String, String) {
    date_path_components_at(now_unix_millis())
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn date_path_components_at(millis: u64) -> (String, String, String, String) {
    let seconds = millis / 1_000;
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let stamp = filename_timestamp(seconds, millis % 1_000, year, month, day);
    (
        format!("{year:04}"),
        format!("{month:02}"),
        format!("{day:02}"),
        stamp,
    )
}

fn timestamp_from_millis(millis: u64) -> String {
    let seconds = millis / 1_000;
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let within_day = seconds % 86_400;
    let hour = within_day / 3_600;
    let minute = (within_day % 3_600) / 60;
    let second = within_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        millis % 1_000
    )
}

fn filename_timestamp(seconds: u64, millis: u64, year: i64, month: i64, day: i64) -> String {
    let within_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}-{:02}-{:02}-{millis:03}Z",
        within_day / 3_600,
        (within_day % 3_600) / 60,
        within_day % 60,
    )
}

/// Parse a recorded `YYYY-MM-DDTHH:MM:SS(.mmm)Z` stamp back into unix seconds
/// so readers can render durable records on the same clock as live rows.
pub fn unix_seconds_from_timestamp(timestamp: &str) -> Option<u64> {
    let (date, rest) = timestamp.split_once('T')?;
    let time = rest.split(['.', 'Z']).next()?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<i64>().ok()?;
    let day = date_parts.next()?.parse::<i64>().ok()?;
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u64>().ok()?;
    let minute = time_parts.next()?.parse::<u64>().ok()?;
    let second = time_parts.next()?.parse::<u64>().ok()?;
    let days = days_from_civil(year, month, day);
    let seconds = days.checked_mul(86_400)? + (hour * 3_600 + minute * 60 + second) as i64;
    u64::try_from(seconds).ok()
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_epoch_and_leap_day_in_utc() {
        assert_eq!(timestamp_from_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            timestamp_from_millis(1_709_164_800_123),
            "2024-02-29T00:00:00.123Z"
        );
    }

    #[test]
    fn parses_recorded_stamps_back_to_the_same_second() {
        for millis in [0, 1_709_164_800_123, 1_753_660_827_583] {
            let stamp = timestamp_from_millis(millis);
            assert_eq!(
                unix_seconds_from_timestamp(&stamp),
                Some(millis / 1_000),
                "{stamp}"
            );
        }
    }

    #[test]
    fn rejects_stamps_it_cannot_place_on_the_clock() {
        for stamp in ["", "not-a-timestamp", "2026-07-28", "2026-07-28T00:00Z"] {
            assert_eq!(unix_seconds_from_timestamp(stamp), None, "{stamp}");
        }
    }
}
