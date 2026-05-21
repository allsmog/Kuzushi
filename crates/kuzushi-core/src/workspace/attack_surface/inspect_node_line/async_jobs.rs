use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    if !inspection.has_any(&[
        "cron.schedule(",
        "new queue(",
        "new worker(",
        "@processor(",
        "@process(",
        "queue(",
        "agenda.define(",
        ".process(",
        ".consume(",
        ".subscribe(",
        "kafka.consumer",
        "consumer.run(",
        "sqs.receive",
        "sqsclient",
        "pubsub.subscription",
        "createconsumer(",
        "nats.subscribe",
        "redis.subscribe",
        "setinterval(",
    ]) {
        return;
    }
    inspection.add_surface(
        builder,
        AttackSurfaceKind::BackgroundJob,
        "Background job or scheduler",
        None,
        None,
        Some("async_job"),
        "node.background-job",
    );
}
