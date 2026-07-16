use super::super::*;

pub(super) fn health_lines(health: &RunLifecycleHealth) -> Vec<String> {
    vec![
        integrity_label(&health.integrity),
        durability_label(&health.durability),
        progress_fidelity_label(&health.progress),
        delivery_label(&health.delivery),
        derivative_delivery_label(&health.derivative_delivery),
    ]
}

fn derivative_delivery_label(delivery: &RunDerivativeDeliveryHealth) -> String {
    match delivery {
        RunDerivativeDeliveryHealth::NotObserved => {
            "Derivatives: not observed on this surface".to_string()
        }
        RunDerivativeDeliveryHealth::Current { through_seq } => {
            format!("Derivatives: current through seq {through_seq}")
        }
        RunDerivativeDeliveryHealth::CatchingUp {
            applied_seq,
            durable_seq,
        } => format!("Derivatives: catching up · applied {applied_seq}/{durable_seq}"),
        RunDerivativeDeliveryHealth::Failed {
            applied_seq,
            durable_seq,
            stage,
            detail,
        } => format!(
            "Derivatives: failed at {stage:?} after seq {applied_seq}/{durable_seq} · {detail}"
        ),
    }
}

fn integrity_label(integrity: &ProjectionHealth) -> String {
    match integrity {
        ProjectionHealth::Healthy => "Stream: healthy".to_string(),
        ProjectionHealth::LegacyLossy => "Stream: legacy and lossy".to_string(),
        ProjectionHealth::Degraded {
            valid_through_seq,
            reason,
        } => format!("Stream: degraded through seq {valid_through_seq} · {reason}"),
    }
}

fn durability_label(durability: &RunDurabilityHealth) -> String {
    match durability {
        RunDurabilityHealth::Durable { through_seq } => {
            format!("Durability: durable through seq {through_seq}")
        }
        RunDurabilityHealth::Failed {
            last_durable_seq,
            stage,
            detail,
            execution_may_have_occurred,
        } => format!(
            "Durability: failed at {stage:?} after seq {last_durable_seq} · execution may have occurred={execution_may_have_occurred} · {detail}"
        ),
    }
}

fn progress_fidelity_label(progress: &RunProgressFidelity) -> String {
    match progress {
        RunProgressFidelity::Complete => "Progress: complete".to_string(),
        RunProgressFidelity::Coalesced { omitted } => {
            format!("Progress: healthy but lossy · {omitted} update(s) omitted")
        }
        RunProgressFidelity::Saturated { omitted_at_least } => {
            format!("Progress: saturated · at least {omitted_at_least} update(s) omitted")
        }
    }
}

fn delivery_label(delivery: &RunDeliveryHealth) -> String {
    match delivery {
        RunDeliveryHealth::Current { through_seq } => {
            format!("Delivery: current through seq {through_seq}")
        }
        RunDeliveryHealth::CatchingUp {
            applied_seq,
            durable_seq,
        } => format!("Delivery: catching up · applied {applied_seq}/{durable_seq}"),
        RunDeliveryHealth::Failed {
            applied_seq,
            stage,
            detail,
        } => format!("Delivery: failed at {stage:?} after seq {applied_seq} · {detail}"),
    }
}

pub fn cost_label(cost: RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return "cost unavailable".to_string();
    }
    if cost.is_complete() {
        return format!("${:.4} exact", cost.observed_usd());
    }
    format!(">=${:.4} incomplete", cost.observed_usd())
}
