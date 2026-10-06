use super::python_route_frameworks::PythonRouteFrameworks;
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;

/// Per-file text scan with memoized whole-text predicates so per-line
/// inspectors never rescan the full source for every line.
pub(crate) struct SourceTextScan<'t> {
    text: &'t str,
    lower: OnceCell<String>,
    memo: RefCell<HashMap<&'static str, bool>>,
    python_routes: OnceCell<PythonRouteFrameworks>,
}

impl<'t> SourceTextScan<'t> {
    pub(crate) fn new(text: &'t str) -> Self {
        Self {
            text,
            lower: OnceCell::new(),
            memo: RefCell::new(HashMap::new()),
            python_routes: OnceCell::new(),
        }
    }

    pub(crate) fn text(&self) -> &'t str {
        self.text
    }

    pub(crate) fn python_route_framework(&self, receiver: &str) -> Option<&'static str> {
        self.python_routes
            .get_or_init(|| PythonRouteFrameworks::from_source(self.text))
            .framework(receiver)
    }

    /// Memoized `text.to_ascii_lowercase().contains(needle)`.
    pub(crate) fn contains_ci(&self, needle: &'static str) -> bool {
        *self
            .memo
            .borrow_mut()
            .entry(needle)
            .or_insert_with(|| self.lowered().contains(needle))
    }

    pub(crate) fn contains_any_ci(&self, needles: &[&'static str]) -> bool {
        needles.iter().any(|needle| self.contains_ci(needle))
    }

    fn lowered(&self) -> &str {
        self.lower.get_or_init(|| self.text.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_ci_matches_lowered_text_and_memoizes() {
        let scan = SourceTextScan::new("from Sanic import Sanic");
        assert!(scan.contains_ci("sanic"));
        assert!(scan.contains_ci("sanic"));
        assert!(!scan.contains_ci("falcon"));
        assert_eq!(scan.text(), "from Sanic import Sanic");
    }

    #[test]
    fn contains_any_ci_short_circuits_on_first_hit() {
        let scan = SourceTextScan::new("use rocket::get;");
        assert!(scan.contains_any_ci(&["rocket::", "use rocket"]));
        assert!(!scan.contains_any_ci(&["axum", "warp::"]));
    }
}
