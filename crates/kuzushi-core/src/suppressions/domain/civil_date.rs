use anyhow::{bail, Result};

/// Convert a civil `YYYY-MM-DD` date (UTC midnight) to unix seconds.
///
/// Pure — no clock, no dependency on a date crate (the repo convention is
/// raw `u64` unix seconds). Uses Howard Hinnant's days-from-civil algorithm.
/// Rejects malformed input explicitly rather than guessing.
pub fn parse_utc_date_to_unix(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    let mut parts = trimmed.split('-');
    let year = next_field(&mut parts, "year")?;
    let month = next_field(&mut parts, "month")?;
    let day = next_field(&mut parts, "day")?;
    if parts.next().is_some() {
        bail!("date {trimmed:?} must be YYYY-MM-DD");
    }
    validate_range(month, 1, 12, "month", trimmed)?;
    validate_range(day, 1, days_in_month(year, month), "day", trimmed)?;
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400)
}

fn next_field<'a>(parts: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<i64> {
    let raw = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("date is missing its {name} field; expected YYYY-MM-DD"))?;
    raw.parse::<i64>()
        .map_err(|_| anyhow::anyhow!("date {name} field {raw:?} is not a number"))
}

fn validate_range(value: i64, low: i64, high: i64, name: &str, whole: &str) -> Result<()> {
    if value < low || value > high {
        bail!("date {name} {value} out of range in {whole:?}");
    }
    Ok(())
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    const LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if month == 2 && is_leap(year) {
        return 29;
    }
    LENGTHS[(month - 1) as usize]
}

/// Days since the unix epoch (1970-01-01). Howard Hinnant, `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_zero() {
        assert_eq!(parse_utc_date_to_unix("1970-01-01").unwrap(), 0);
    }

    #[test]
    fn known_dates_match_unix_seconds() {
        assert_eq!(parse_utc_date_to_unix("2000-01-01").unwrap(), 946_684_800);
        assert_eq!(parse_utc_date_to_unix("2026-12-31").unwrap(), 1_798_675_200);
        assert_eq!(parse_utc_date_to_unix("2021-01-01").unwrap(), 1_609_459_200);
    }

    #[test]
    fn leap_day_is_accepted_and_non_leap_rejected() {
        assert!(parse_utc_date_to_unix("2024-02-29").is_ok());
        assert!(parse_utc_date_to_unix("2023-02-29").is_err());
    }

    #[test]
    fn malformed_dates_are_rejected() {
        assert!(parse_utc_date_to_unix("2026-13-01").is_err());
        assert!(parse_utc_date_to_unix("2026-00-10").is_err());
        assert!(parse_utc_date_to_unix("2026-01-32").is_err());
        assert!(parse_utc_date_to_unix("not-a-date").is_err());
        assert!(parse_utc_date_to_unix("2026-01").is_err());
        assert!(parse_utc_date_to_unix("2026-01-01-01").is_err());
    }
}
