use kuzushi_core::scan::{scan_sbom, ScanCancellation};
use std::fs;
use std::time::{Duration, Instant};

const DEFAULT_ITERATIONS: usize = 25;
const FIXTURE_DIRECTORIES: usize = 200;

fn main() {
    let fixture = build_fixture();
    let iterations = benchmark_iterations();
    let cancellation = ScanCancellation::default();
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let report = scan_sbom(fixture.path(), &cancellation).expect("scan benchmark fixture");
        assert_eq!(report.manifests_scanned, FIXTURE_DIRECTORIES);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    print_receipt(&samples);
}

fn build_fixture() -> tempfile::TempDir {
    let fixture = tempfile::tempdir().expect("create benchmark fixture");
    for index in 0..FIXTURE_DIRECTORIES {
        let directory = fixture.path().join(format!("package-{index:04}"));
        fs::create_dir(&directory).expect("create fixture directory");
        fs::write(
            directory.join("package.json"),
            r#"{"dependencies":{"serde":"1.0.0"}}"#,
        )
        .expect("write fixture manifest");
        fs::write(directory.join("source.rs"), "fn main() {}\n").expect("write source noise");
    }
    fixture
}

fn benchmark_iterations() -> usize {
    std::env::var("KUZUSHI_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ITERATIONS)
}

fn print_receipt(samples: &[Duration]) {
    let total = samples.iter().sum::<Duration>();
    let median = samples[samples.len() / 2];
    println!(
        "sbom_inventory iterations={} fixture_files={} median_ms={:.3} mean_ms={:.3}",
        samples.len(),
        FIXTURE_DIRECTORIES * 2,
        median.as_secs_f64() * 1_000.0,
        total.as_secs_f64() * 1_000.0 / samples.len() as f64,
    );
}
