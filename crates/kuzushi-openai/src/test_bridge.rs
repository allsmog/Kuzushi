//! Synthetic transport fixtures use the real host admission protocol. No network.
use crate::LangGraphRuntime;
use kuzushi_core::allowance::{
    AllowanceApprovalV1, AllowanceBinding, AllowanceLimits, AllowanceWork, InvestigationWork,
};
use kuzushi_core::SpendLimiter;
use std::sync::Arc;

const HARNESS: &str = r#"
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const { readBridgeRequest, openProviderAdmission, withProviderAdmission } =
  await import(pathToFileURL(process.argv[2]));
const command = JSON.parse(process.argv[3]);
const request = await readBridgeRequest(process.stdin);
await openProviderAdmission(request, text => process.stdout.write(text));
async function invokeFixture() {
  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), { stdio: ['pipe','pipe','pipe'] });
    const stdout = [], stderr = [];
    child.stdout.on('data', value => stdout.push(value));
    child.stderr.on('data', value => stderr.push(value));
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }));
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(request));
  });
}
const result = await withProviderAdmission(request, invokeFixture, () => ({ costUsd: undefined }));
if (request.responseEvents === 'text-v1') {
  try { process.stdout.write('\x1e'+JSON.stringify({ type:'result', result:JSON.parse(result.stdout) })+'\n'); }
  catch { process.stdout.write(result.stdout); }
} else process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.stdin.destroy();
process.exitCode = result.code ?? 1;
"#;

pub(crate) fn approved(
    mut runtime: LangGraphRuntime,
    model: &str,
    calls: u32,
) -> (tempfile::TempDir, LangGraphRuntime) {
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("synthetic-bridge.mjs");
    std::fs::write(&script, HARNESS).unwrap();
    let module = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/langgraph-bridge/provider-admission.mjs");
    runtime.command = vec![
        "node".into(),
        script.display().to_string(),
        module.display().to_string(),
        serde_json::to_string(&runtime.command).unwrap(),
    ];
    runtime.allowance = Some(binding(root.path(), model, calls));
    (root, runtime)
}

fn binding(root: &std::path::Path, model: &str, calls: u32) -> AllowanceBinding {
    let ledger = Arc::new(SpendLimiter::open(root.join("ledger.sqlite3")).unwrap());
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "synthetic-transport".into(),
            expected_revision: 0,
            model: model.into(),
            limits: AllowanceLimits {
                max_provider_calls: calls,
                protected_review_calls: 0,
            },
            reason: "Explicit finite synthetic transport fixture; no live provider".into(),
            work_plan: None,
        })
        .unwrap();
    AllowanceBinding::new(
        ledger,
        AllowanceWork {
            investigation_id: "synthetic-transport".into(),
            revision: 1,
            run_id: "fixture-run".into(),
            work_id: "fixture-query".into(),
            model: model.into(),
            work: InvestigationWork::Context,
        },
    )
    .unwrap()
}
