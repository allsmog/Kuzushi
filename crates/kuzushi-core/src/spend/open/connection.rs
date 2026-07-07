use super::*;

impl SpendLimiter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_hard_ceiling(path, None)
    }

    pub fn open_with_hard_ceiling(
        path: impl AsRef<Path>,
        hard_ceiling: Option<f64>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let conn = crate::sqlite_connection::open_file(path)
            .with_context(|| format!("could not open spend ledger at {}", path.display()))?;
        Self::with_connection_and_hard_ceiling(conn, hard_ceiling)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::open_in_memory_with_hard_ceiling(None)
    }

    pub fn open_in_memory_with_hard_ceiling(hard_ceiling: Option<f64>) -> Result<Self> {
        let conn = Connection::open_in_memory().context("could not open in-memory spend ledger")?;
        Self::with_connection_and_hard_ceiling(conn, hard_ceiling)
    }

    pub(crate) fn with_connection_and_hard_ceiling(
        conn: Connection,
        hard_ceiling: Option<f64>,
    ) -> Result<Self> {
        if let Some(value) = hard_ceiling {
            anyhow::ensure!(
                value.is_finite() && value >= 0.0,
                "hard ceiling must be a finite non-negative number, got {value}"
            );
        }
        ensure_schema(&conn)?;
        let caps = load_caps(&conn)?;
        Ok(Self {
            state: Mutex::new(LimiterState {
                conn,
                caps,
                hard_ceiling,
            }),
        })
    }
}
