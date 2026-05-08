use super::*;

impl SpendLimiter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("could not open spend ledger at {}", path.display()))?;
        Self::with_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("could not open in-memory spend ledger")?;
        Self::with_connection(conn)
    }

    pub(crate) fn with_connection(conn: Connection) -> Result<Self> {
        ensure_schema(&conn)?;
        let caps = load_caps(&conn)?;
        let hard_ceiling = read_hard_ceiling_from_env();
        Ok(Self {
            state: Mutex::new(LimiterState {
                conn,
                caps,
                hard_ceiling,
            }),
        })
    }
}
