use anyhow::{ensure, Context, Result};
use kuzushi_core::{
    allowance::{AllowanceBinding, AllowanceReservation},
    runtime::RuntimeCostReport,
    ScanCancellation,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Write;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub(super) const ADMISSION_PROTOCOL: &str = "stdio-v1";

#[derive(Clone)]
pub(super) struct AdmissionHandshake {
    ready: Arc<AtomicBool>,
    deadline: Instant,
}

impl AdmissionHandshake {
    fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    pub(super) fn check(&self) -> Result<()> {
        if !self.ready.load(Ordering::Acquire) && Instant::now() >= self.deadline {
            return Err(kuzushi_core::RuntimeFailure::allowance_handshake_timeout().into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AdmissionAction {
    Hello {
        protocol: u32,
    },
    Reserve {
        model: String,
    },
    Settle {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "costUsd")]
        cost_usd: Option<f64>,
    },
}

/// One bridge has at most one provider request in flight. Parallel workers get
/// separate sessions and share atomic admission through the durable binding.
pub(super) struct ProviderAdmission {
    binding: AllowanceBinding,
    replies: Box<dyn Write + Send>,
    cancellation: Option<ScanCancellation>,
    pending: Option<AllowanceReservation>,
    hello: bool,
    refused: bool,
    handshake: AdmissionHandshake,
}

impl ProviderAdmission {
    pub(super) fn new(
        binding: AllowanceBinding,
        replies: impl Write + Send + 'static,
        cancellation: Option<ScanCancellation>,
    ) -> Self {
        Self {
            binding,
            replies: Box::new(replies),
            cancellation,
            pending: None,
            hello: false,
            refused: false,
            handshake: AdmissionHandshake::new(),
        }
    }

    pub(super) fn handshake(&self) -> AdmissionHandshake {
        self.handshake.clone()
    }

    pub(super) fn handle(&mut self, action: AdmissionAction) -> Result<()> {
        match action {
            AdmissionAction::Hello { protocol } => self.hello(protocol),
            AdmissionAction::Reserve { model } => self.reserve(&model),
            AdmissionAction::Settle {
                request_id,
                cost_usd,
            } => self.settle(&request_id, cost_usd),
        }
    }

    pub(super) fn finish(&self, result: &Value) -> Result<()> {
        if !self.hello {
            return Err(kuzushi_core::RuntimeFailure::allowance_unsupported().into());
        }
        if result.get("ok").and_then(Value::as_bool) == Some(true) {
            ensure!(
                self.pending.is_none(),
                "bridge completed without a provider-call receipt"
            );
        }
        Ok(())
    }

    fn hello(&mut self, protocol: u32) -> Result<()> {
        ensure!(
            protocol == 1 && !self.hello,
            "invalid provider-admission handshake"
        );
        self.hello = true;
        self.reply(json!({"type":"ready", "protocol":1}))?;
        self.handshake.ready.store(true, Ordering::Release);
        Ok(())
    }

    fn reserve(&mut self, model: &str) -> Result<()> {
        ensure!(self.hello, "provider request preceded admission handshake");
        ensure!(
            self.pending.is_none(),
            "provider requested another call before settlement"
        );
        self.ensure_active()?;
        if self.refused {
            return self.refuse();
        }
        self.reserve_active(model)
    }

    fn reserve_active(&mut self, model: &str) -> Result<()> {
        let reservation = match self.binding.reserve(model) {
            Ok(reservation) => reservation,
            Err(_) => return self.refuse(),
        };
        let response = json!({"type":"admitted", "requestId":reservation.request_id()});
        self.pending = Some(reservation);
        self.reply(response)
    }

    fn refuse(&mut self) -> Result<()> {
        self.refused = true;
        self.reply(json!({"type":"refused"}))
    }

    fn settle(&mut self, request_id: &str, cost_usd: Option<f64>) -> Result<()> {
        let pending = self
            .pending
            .as_ref()
            .context("provider receipt has no reservation")?;
        ensure!(
            pending.request_id() == request_id,
            "provider receipt reservation mismatch"
        );
        let cost = cost_usd
            .map(|cost| RuntimeCostReport::from_optional(Some(cost), "provider receipt cost"))
            .transpose()?
            .unwrap_or(RuntimeCostReport::UNAVAILABLE);
        let pending = self
            .pending
            .take()
            .context("provider reservation disappeared")?;
        self.binding.settle(pending, cost)?;
        self.reply(json!({"type":"settled", "requestId":request_id}))
    }

    fn ensure_active(&self) -> Result<()> {
        ensure!(
            !self
                .cancellation
                .as_ref()
                .is_some_and(ScanCancellation::is_cancelled),
            "provider admission cancelled"
        );
        Ok(())
    }

    fn reply(&mut self, response: Value) -> Result<()> {
        serde_json::to_writer(&mut self.replies, &response)?;
        self.replies.write_all(b"\n")?;
        self.replies.flush()?;
        Ok(())
    }
}
