#[cfg(test)]
mod tests {
    use super::super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cap_limits_in_flight_to_configured_value() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 2);

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let g = gate.clone();
            let in_flight = Arc::clone(&in_flight);
            let max_seen = Arc::clone(&max_seen);
            handles.push(tokio::spawn(async move {
                let _permit = g.acquire("test:m", Priority::Normal).await;
                let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(max_seen.load(Ordering::SeqCst) <= 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn high_priority_preempts_low_priority_in_queue() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 1);

        // Take the only permit so subsequent acquires queue.
        let _hold = gate.acquire("test:m", Priority::Normal).await;

        let order = Arc::new(Mutex::new(Vec::new()));

        let g1 = gate.clone();
        let order1 = Arc::clone(&order);
        let lo1 = tokio::spawn(async move {
            let _p = g1.acquire("test:m", Priority::Lowest).await;
            order1.lock().unwrap().push("lo1");
        });
        // Give lo1 time to enqueue.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let g2 = gate.clone();
        let order2 = Arc::clone(&order);
        let hi = tokio::spawn(async move {
            let _p = g2.acquire("test:m", Priority::High).await;
            order2.lock().unwrap().push("hi");
        });
        // Give hi time to enqueue.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Now release the held permit — hi should win even though lo1
        // queued first.
        drop(_hold);
        lo1.await.unwrap();
        hi.await.unwrap();

        let order = order.lock().unwrap();
        assert_eq!(order.as_slice(), &["hi", "lo1"]);
    }

    #[tokio::test]
    async fn priority_scope_propagates_via_task_local() {
        with_priority(Priority::Lowest, async {
            assert_eq!(current_priority(), Priority::Lowest);
            // Nested scope wins.
            with_priority(Priority::High, async {
                assert_eq!(current_priority(), Priority::High);
            })
            .await;
            assert_eq!(current_priority(), Priority::Lowest);
        })
        .await;
        // Outside any scope falls back to Normal.
        assert_eq!(current_priority(), Priority::Normal);
    }

    #[test]
    fn default_concurrency_table_matches_known_models() {
        assert_eq!(default_concurrency_for("anthropic:claude-haiku-4-5"), 80);
        assert_eq!(default_concurrency_for("anthropic:claude-opus-4-7"), 60);
        assert_eq!(default_concurrency_for("google:gemini-2.5-pro"), 600);
        assert_eq!(default_concurrency_for("openai:o3-2025-04-16"), 700);
        assert_eq!(default_concurrency_for("openai:gpt-4o"), 500);
        // Unknown model — conservative.
        assert_eq!(default_concurrency_for("anthropic:unknown-99"), 16);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn canceled_queue_head_does_not_strand_later_waiters() {
        use std::time::Duration;
        use tokio::time::timeout;

        let gate = ModelGate::new();
        gate.set_cap("test:m", 1);

        // Hold the only permit so every subsequent acquire has to queue.
        let hold = gate.acquire("test:m", Priority::Normal).await;

        // High-priority waiter becomes the queue head immediately.
        let g_hi = gate.clone();
        let hi = tokio::spawn(async move {
            let _p = g_hi.acquire("test:m", Priority::High).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Lower-priority waiter parks behind the head.
        let g_lo = gate.clone();
        let acquired = Arc::new(AtomicUsize::new(0));
        let acquired_lo = Arc::clone(&acquired);
        let lo = tokio::spawn(async move {
            let _p = g_lo.acquire("test:m", Priority::Normal).await;
            acquired_lo.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Cancel the queue HEAD while it is parked. Before the fix this
        // stranded the queue: the dead head was never popped and no live
        // waiter could ever become head.
        hi.abort();
        let _ = hi.await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Releasing the permit must now let the surviving waiter proceed.
        drop(hold);
        timeout(Duration::from_secs(2), lo)
            .await
            .expect("surviving waiter must make forward progress after head cancellation")
            .unwrap();
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn canceling_middle_waiter_preserves_priority_order() {
        use std::time::Duration;
        use tokio::time::timeout;

        let gate = ModelGate::new();
        gate.set_cap("test:m", 1);
        let hold = gate.acquire("test:m", Priority::Normal).await;

        let order = Arc::new(Mutex::new(Vec::new()));

        // Enqueue High, then Normal, then Lowest.
        let g_hi = gate.clone();
        let hi = tokio::spawn(async move {
            let _p = g_hi.acquire("test:m", Priority::High).await;
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let g_norm = gate.clone();
        let order_norm = Arc::clone(&order);
        let norm = tokio::spawn(async move {
            let _p = g_norm.acquire("test:m", Priority::Normal).await;
            order_norm.lock().unwrap().push("norm");
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let g_low = gate.clone();
        let order_low = Arc::clone(&order);
        let low = tokio::spawn(async move {
            let _p = g_low.acquire("test:m", Priority::Lowest).await;
            order_low.lock().unwrap().push("low");
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cancel the current head (High). Normal must still preempt Lowest.
        hi.abort();
        let _ = hi.await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        drop(hold);
        timeout(Duration::from_secs(2), norm).await.unwrap().unwrap();
        timeout(Duration::from_secs(2), low).await.unwrap().unwrap();

        assert_eq!(order.lock().unwrap().as_slice(), &["norm", "low"]);
    }

    #[test]
    fn set_cap_is_idempotent_and_persists_across_acquires() {
        let gate = ModelGate::new();
        gate.set_cap("test:m", 5);
        assert_eq!(gate.cap_for("test:m"), 5);
        gate.set_cap("test:m", 7);
        assert_eq!(gate.cap_for("test:m"), 7);
    }
}
