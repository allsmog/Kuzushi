use std::fmt;
use std::sync::Arc;

/// Ephemeral public response text. This is not a completed answer or an audit event.
#[derive(Clone, PartialEq, Eq)]
pub enum ResponseTextEvent {
    Reset,
    Delta(String),
}

impl fmt::Debug for ResponseTextEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reset => formatter.write_str("ResponseTextEvent::Reset"),
            Self::Delta(text) => formatter
                .debug_tuple("ResponseTextEvent::DeltaBytes")
                .field(&text.len())
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct ResponseTextObserver(Arc<dyn Fn(ResponseTextEvent) + Send + Sync>);

impl ResponseTextObserver {
    pub fn new(observer: impl Fn(ResponseTextEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(observer))
    }

    pub(crate) fn emit(&self, event: ResponseTextEvent) {
        (self.0)(event);
    }
}

impl fmt::Debug for ResponseTextObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseTextObserver")
    }
}
