use super::*;
pub(super) const MODEL: &str = "openai-codex:gpt-5.5";
const PROVIDER: &str = r#"
import assert from 'node:assert/strict';
import { appendFileSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
const mode = readFileSync(join(root, 'mode'), 'utf8');
appendFileSync(join(root, 'bridge-starts'), 'start\n');
if (mode === 'quota') {
  const schedule = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay, ...args) => schedule(callback, Math.min(delay, 1), ...args);
}
globalThis.fetch = async (_url, init) => {
  const body = JSON.parse(init.body);
  assert.equal(body.model, 'gpt-5.5');
  assert.deepEqual(body.reasoning, { effort: 'medium' });
  appendFileSync(join(root, 'provider-calls'), JSON.stringify({model:body.model,tools:!!body.tools?.length})+'\n');
  if (mode === 'fail') return new Response('{"error":{"message":"offline failure"}}', {status:503});
  if (mode === 'quota') return new Response('{"error":{"message":"offline quota"}}', {status:429});
  if (mode === 'cancel') return new Response(new ReadableStream({start(controller) {
    controller.enqueue(new TextEncoder().encode('data: '+JSON.stringify({type:'response.output_text.delta',delta:'partial response'})+'\n\n'));
  }}));
  if (mode === 'context') {
    const text = JSON.stringify({schemaVersion:1,customMiddleware:[],customSanitizers:[],trustBoundaries:[],dataClassifications:[],architecturalNotes:[]});
    return new Response('data: '+JSON.stringify({type:'response.output_text.done',text})+'\n\ndata: '+JSON.stringify({type:'response.completed',response:{status:'completed',usage:{input_tokens:2,output_tokens:3}}})+'\n\n');
  }
  const events = body.tools?.length ? [{type:'response.output_item.done',item:{type:'function_call',call_id:crypto.randomUUID(),name:body.tools[0].name,arguments:JSON.stringify({path:root})}}]
    : [{type:'response.output_text.done',text:'bounded conclusion'}];
  events.push({type:'response.completed',response:{status:'completed',usage:{input_tokens:2,output_tokens:3}}});
  return new Response(events.map(event => 'data: '+JSON.stringify(event)+'\n\n').join(''));
};
"#;

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    pub(super) ledger: Arc<SpendLimiter>,
    pub(super) binding: AllowanceBinding,
    pub(super) runtime: LangGraphRuntime,
}

impl Fixture {
    pub(super) fn new(mode: &str, calls: u32, review: u32) -> Self {
        let root = tempdir().unwrap();
        fs::write(root.path().join("provider.mjs"), PROVIDER).unwrap();
        fs::write(root.path().join("mode"), mode).unwrap();
        fs::write(
            root.path().join("oauth.json"),
            r#"{"openai-codex":{"access":"offline-fixture","expires":99999999999999}}"#,
        )
        .unwrap();
        let ledger = Arc::new(SpendLimiter::open(root.path().join("ledger.sqlite3")).unwrap());
        let binding = approve(&ledger, calls, review);
        let runtime = fixture_runtime(root.path());
        Self {
            root,
            ledger,
            binding,
            runtime,
        }
    }

    pub(super) fn request(&self, tools: bool) -> AgentQueryRequest {
        let mut request = AgentQueryRequest::new(
            MODEL,
            self.root.path(),
            "Offline accounting test",
            "Inspect source only",
        )
        .with_thinking_level("medium");
        if tools {
            request.tool_policy = AgentToolPolicy::new("source-read-only", ["LS"]);
            request.tool_policy.mcp_read_roots = vec![self.root.path().to_path_buf()];
        }
        request
    }

    pub(super) fn provider_calls(&self) -> usize {
        fs::read_to_string(self.root.path().join("provider-calls"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    pub(super) fn query(&self, tools: bool) -> anyhow::Result<kuzushi_core::AgentQueryResponse> {
        self.runtime
            .with_allowance_binding(self.binding.clone())
            .unwrap()
            .query_blocking(self.request(tools))
    }
}

fn approve(ledger: &Arc<SpendLimiter>, calls: u32, review: u32) -> AllowanceBinding {
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "offline-study".into(),
            expected_revision: 0,
            model: MODEL.into(),
            limits: AllowanceLimits {
                max_provider_calls: calls,
                protected_review_calls: review,
            },
            reason: "Offline fixture allowance; no live network".into(),
            work_plan: None,
        })
        .unwrap();
    AllowanceBinding::new(
        ledger.clone(),
        AllowanceWork {
            investigation_id: "offline-study".into(),
            revision: 1,
            run_id: "offline-run".into(),
            work_id: "source-scan".into(),
            model: MODEL.into(),
            work: InvestigationWork::Discovery,
        },
    )
    .unwrap()
}

fn fixture_runtime(root: &std::path::Path) -> LangGraphRuntime {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut runtime = LangGraphRuntime::from_config(&V2Config::default(), &source).unwrap();
    runtime.command = vec![
        "node".into(),
        "--import".into(),
        root.join("provider.mjs").display().to_string(),
        source
            .join("scripts/langgraph-bridge.mjs")
            .display()
            .to_string(),
    ];
    runtime.oauth_credentials_path = root.join("oauth.json");
    runtime.api_key = None;
    runtime.api_key_env = "OPENAI_API_KEY".into();
    runtime.retry.attempts = Some(4);
    runtime.retry.backoff_ms = 1;
    runtime.thinking_level = Some("medium".into());
    runtime
}
