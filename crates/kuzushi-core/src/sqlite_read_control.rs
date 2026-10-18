//! Interrupt ledger SQL and remove its callback before returning the connection.
use crate::ScanCancellation;
use anyhow::Result;
use rusqlite::Connection;

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
    let mut guard = ReadCancellation::install(connection, cancellation)?;
    let result = query();
    guard.clear()?;
    check(cancellation)?;
    result
}

struct ReadCancellation<'a> {
    connection: &'a Connection,
    installed: bool,
}

impl<'a> ReadCancellation<'a> {
    fn install(
        connection: &'a Connection,
        cancellation: Option<&ScanCancellation>,
    ) -> Result<Self> {
        check(cancellation)?;
        let mut guard = Self {
            connection,
            installed: false,
        };
        if let Some(cancellation) = cancellation {
            let cancellation = cancellation.clone();
            connection.progress_handler(1000, Some(move || cancellation.is_cancelled()))?;
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
