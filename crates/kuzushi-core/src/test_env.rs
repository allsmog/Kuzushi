use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard, OnceLock};

pub(crate) fn codeql_bin_env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

pub(crate) fn joern_env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// One process-wide lock for `KUZUSHI_MCP_CLANG_BIN`. Both the uaf-hunt
/// report tests and the clang_subprocess adapter tests mutate this var;
/// two separate mutexes would let them race each other.
pub(crate) fn mcp_clang_env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// One lock for the config-bootstrap env family (`KUZUSHI_*` overrides,
/// `HOME`): `load_config` reads these on many parallel test threads, so
/// mutators must not interleave.
pub(crate) fn config_env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

/// Panic-safe environment mutation for tests: the previous value is
/// restored on drop, so an assertion failure between set and restore
/// cannot leak the mutation into every later test in the process.
/// Callers must hold the variable's process-wide lock for the guard's
/// whole lifetime — this guard provides restoration, not exclusion.
pub(crate) struct ScopedEnv {
    key: String,
    previous: Option<OsString>,
}

impl ScopedEnv {
    pub(crate) fn set(key: impl Into<String>, value: impl AsRef<OsStr>) -> Self {
        let key = key.into();
        let previous = std::env::var_os(&key);
        std::env::set_var(&key, value);
        Self { key, previous }
    }

    pub(crate) fn unset(key: impl Into<String>) -> Self {
        let key = key.into();
        let previous = std::env::var_os(&key);
        std::env::remove_var(&key);
        Self { key, previous }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(&self.key, value),
            None => std::env::remove_var(&self.key),
        }
    }
}
