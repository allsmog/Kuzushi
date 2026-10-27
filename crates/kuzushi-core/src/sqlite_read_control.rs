//! Interrupt ledger SQL and remove its callback before returning the connection.
use crate::ScanCancellation;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::time::{Duration, Instant};

pub(crate) fn check(cancellation: Option<&ScanCancellation>) -> Result<()> {
    anyhow::ensure!(
        !cancellation.is_some_and(ScanCancellation::is_cancelled),
        "Read cancelled"
    );
    Ok(())
}

pub(crate) fn read<T>(
    connection: &Connection,
    cancellation: Option<&ScanCancellation>,
    query: impl FnOnce() -> Result<T>,
) -> Result<T> {
    controlled_read(connection, cancellation, None, query)
}

pub(crate) fn read_with_timeout<T>(
    connection: &Connection,
    cancellation: Option<&ScanCancellation>,
    timeout: Duration,
    query: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("Invalid read timeout")?;
    controlled_read(connection, cancellation, Some(deadline), query)
}

fn controlled_read<T>(
    connection: &Connection,
    cancellation: Option<&ScanCancellation>,
    deadline: Option<Instant>,
    query: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mut guard = ReadCancellation::install(connection, cancellation, deadline)?;
    let result = query();
    guard.clear()?;
    check(cancellation)?;
    check_deadline(deadline)?;
    result
}

fn check_deadline(deadline: Option<Instant>) -> Result<()> {
    anyhow::ensure!(
        !deadline.is_some_and(|end| Instant::now() >= end),
        "Read exceeded its cooperative time allowance"
    );
    Ok(())
}

fn interrupted(cancellation: Option<&ScanCancellation>, deadline: Option<Instant>) -> bool {
    cancellation.is_some_and(ScanCancellation::is_cancelled)
        || deadline.is_some_and(|end| Instant::now() >= end)
}

struct ReadCancellation<'a> {
    connection: &'a Connection,
    installed: bool,
}

impl<'a> ReadCancellation<'a> {
    fn install(
        connection: &'a Connection,
        cancellation: Option<&ScanCancellation>,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        check(cancellation)?;
        check_deadline(deadline)?;
        let mut guard = Self {
            connection,
            installed: false,
        };
        if cancellation.is_some() || deadline.is_some() {
            let cancellation = cancellation.cloned();
            connection.progress_handler(
                1000,
                Some(move || interrupted(cancellation.as_ref(), deadline)),
            )?;
            guard.installed = true;
        }
        Ok(guard)
    }

    fn clear(&mut self) -> Result<()> {
        if self.installed {
            self.connection.progress_handler(0, None::<fn() -> bool>)?;
            self.installed = false;
        }
        Ok(())
    }
}

impl Drop for ReadCancellation<'_> {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUERY: &str = "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<5000) SELECT max(x) FROM n";

    #[test]
    fn an_expired_read_does_not_execute_or_poison_the_connection() {
        let connection = Connection::open_in_memory().unwrap();
        let result: Result<()> = read_with_timeout(&connection, None, Duration::ZERO, || {
            panic!("expired read must not run")
        });
        assert!(result.unwrap_err().to_string().contains("time allowance"));
        assert_eq!(
            connection
                .query_row("select 1", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn a_deadline_interrupts_sql_and_removes_its_callback() {
        let connection = Connection::open_in_memory().unwrap();
        let result = read_with_timeout(&connection, None, Duration::from_millis(5), || {
            Ok(connection.query_row("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT max(x) FROM n",
                [], |row| row.get::<_, i64>(0))?)
        });
        assert!(result.unwrap_err().to_string().contains("time allowance"));
        assert_eq!(
            connection
                .query_row(QUERY, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5000
        );
    }

    #[test]
    fn cancellation_during_sql_interrupts_work_and_clears_the_handler() {
        let connection = Connection::open_in_memory().unwrap();
        let cancellation = ScanCancellation::default();
        let result: Result<i64> = read(&connection, Some(&cancellation), || {
            cancellation.cancel();
            let error = connection
                .query_row(QUERY, [], |row| row.get::<_, i64>(0))
                .unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::OperationInterrupted)
            );
            Err(error.into())
        });
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert_eq!(
            connection
                .query_row(QUERY, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5000
        );
    }

    #[test]
    fn failed_read_preserves_its_error_and_does_not_leave_a_callback() {
        let connection = Connection::open_in_memory().unwrap();
        let cancellation = ScanCancellation::default();
        let result: Result<()> = read(&connection, Some(&cancellation), || {
            anyhow::bail!("owned read failure")
        });
        assert_eq!(result.unwrap_err().to_string(), "owned read failure");
        cancellation.cancel();
        assert_eq!(
            connection
                .query_row(QUERY, [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5000
        );
    }
}
