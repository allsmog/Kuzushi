"""Prepare owned static source and a finite unapproved real-model study."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from installed_scope_study import current_counts, save
from secret_settings import ledger

MODEL = "openai-codex:gpt-6-luna"
INVESTIGATION = "live-application-review-20261014"
CAMPAIGN = "live-application-scans-20261014"
FIXTURE = Path("/private/tmp/kuzushi-live-application-20261014")
OWNER = Path("/Users/shayaunnejad")

SOURCES = {
    ".gitignore": ".kuzushi/\n",
    "README.md": """# Owned static invoice service
This is an inert library fixture for source review. Never import, build or execute it.
The intended policy is that tenant-facing invoice reads return only that tenant's
records. Request.principal represents an already authenticated caller. Authentication
transport and deployment are outside this fixture. The shared store contains records
from multiple tenants. Review the supplied code for the actual enforcement and its
limits. No server, credentials, network client or executable entry point is supplied.
""",
    "services/__init__.py": '"""Owned static service package. Never execute."""\n',
    "services/gateway/__init__.py": '"""Source-only request adapters."""\n',
    "services/gateway/routes.py": '''"""Tenant-facing source adapter. Never execute."""
from dataclasses import dataclass
from shared.identity import Principal
from services.invoices.service import InvoiceService

@dataclass(frozen=True)
class Request:
    principal: Principal

def invoice_detail(request: Request, invoice_id: str, service: InvoiceService):
    """invoice_id is selected by the authenticated request's caller."""
    return service.lookup(invoice_id)
''',
    "services/gateway/safe_routes.py": '''"""Separate tenant-scoped adapter, supplied for source comparison."""
from services.gateway.routes import Request
from services.invoices.service import InvoiceService

def scoped_invoice_detail(request: Request, invoice_id: str, service: InvoiceService):
    return service.lookup_for_tenant(request.principal, invoice_id)
''',
    "services/invoices/__init__.py": '"""Source-only invoice domain."""\n',
    "services/invoices/entities.py": '''from dataclasses import dataclass

@dataclass(frozen=True)
class Invoice:
    invoice_id: str
    tenant_id: str
    customer_name: str
    amount_cents: int
''',
    "services/invoices/store.py": '''from services.invoices.entities import Invoice

class InvoiceStore:
    """A global identifier index over all tenants; this layer has no caller context."""
    def __init__(self, records: list[Invoice]):
        self.records = {record.invoice_id: record for record in records}

    def read(self, invoice_id: str):
        return self.records.get(invoice_id)
''',
    "services/invoices/service.py": '''from shared.identity import Principal
from shared.policy import belongs_to_tenant
from services.invoices.store import InvoiceStore

class InvoiceService:
    def __init__(self, store: InvoiceStore):
        self.store = store

    def lookup(self, invoice_id: str):
        return self.store.read(invoice_id)

    def lookup_for_tenant(self, principal: Principal, invoice_id: str):
        record = self.store.read(invoice_id)
        if record is None or not belongs_to_tenant(principal, record):
            return None
        return record
''',
    "shared/__init__.py": '"""Shared source-only identity and policy contracts."""\n',
    "shared/identity.py": '''from dataclasses import dataclass

@dataclass(frozen=True)
class Principal:
    """Constructed by the authenticated caller boundary outside this library."""
    subject_id: str
    tenant_id: str
''',
    "shared/policy.py": '''from shared.identity import Principal
from services.invoices.entities import Invoice

def belongs_to_tenant(principal: Principal, invoice: Invoice) -> bool:
    return principal.tenant_id == invoice.tenant_id
''',
    "docs/architecture.md": """# Source contracts
Gateway functions accept an authenticated principal and a caller-selected invoice id.
The invoice service delegates to a global in-memory index. Invoice records retain
their tenant ids. The shared policy compares the principal and record tenant ids.
Both the ordinary and scoped gateway adapters are supplied in this repository.
The concrete source paths determine whether each adapter applies the policy.
No runtime deployment, authentication implementation or external datastore is
provided. Source evidence alone cannot establish any deployed exposure.
""",
}


def source_hashes(root):
    hashes = {}
    for directory, children, files in os.walk(root, followlinks=False):
        children[:] = [name for name in children if name != ".kuzushi"]
        parent = Path(directory)
        assert all(not (parent / name).is_symlink() for name in children + files)
        for name in files:
            path = parent / name
            hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def context_document():
    nodes = [("caller", "Authenticated caller", "external-entity", "caller"),
        ("gateway", "Gateway adapters", "process", "service"),
        ("invoice-service", "Invoice service", "process", "service"),
        ("store", "Global invoice index", "data-store", "service")]
    flows = [("request", "caller", "gateway"), ("lookup", "gateway", "invoice-service"),
        ("read", "invoice-service", "store")]
    return {"version":"1", "methodology":"stride", "title":"Owned invoice source contracts",
        "systemContext":"Owned inert Python library. Gateway adapters accept an already authenticated Principal and a caller-selected invoice id. InvoiceService delegates to a store indexed by global invoice id. Invoice records contain tenant_id. shared/policy.py compares tenant ids; one service method calls that policy. Source includes both gateway adapters. Authentication transport, deployment and external persistence are absent. The source determines enforcement; this manual context contains no finding verdict.",
        "dfd":{"nodes":[{"id":key,"name":name,"type":kind,"trustZone":zone} for key,name,kind,zone in nodes],
            "flows":[{"id":key,"sourceId":source,"targetId":target,"trustBoundaryIds":["caller-boundary"] if key=="request" else []} for key,source,target in flows],
            "trustBoundaries":[{"id":"caller-boundary","name":"Caller to library adapter","innerZone":"service","outerZone":"caller","crossingFlowIds":["request"]}]},
        "threats":[], "openQuestions":[{"id":"deployment","question":"Which adapters are exposed by a deployment? No deployment is supplied.","targetElementIds":["gateway"]}],
        "summary":{"evidenceType":"Manual source-grounded fixture contracts; no model or runtime verification."}}


def seed(root, evidence, home):
    assert root == FIXTURE / "target" and evidence == FIXTURE / "control" and home == FIXTURE / "home"
    assert not (evidence / "source-before.json").exists(), "Reuse the existing fixture; do not overwrite its source or plans"
    root.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    for name, content in SOURCES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    credentials = OWNER / ".kuzushi/oauth-credentials.json"
    assert credentials.is_file(), "Existing stored OAuth is required; no credentials are created"
    repo = Path(__file__).resolve().parents[3]
    config = home / ".kuzushi/v3/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('model = ' + json.dumps(MODEL) + '\n[runtime]\nthinking_level = "low"\nlanggraph_bridge_command = '
        + json.dumps(["node", str(repo / "scripts/langgraph-bridge.mjs")])
        + '\n[runtime.anthropic_oauth]\ncredentials_path = ' + json.dumps(str(credentials)) + '\nallow_env_token = false\n')
    (root / ".kuzushi").mkdir(exist_ok=True)
    save(root / ".kuzushi", "manual-context", context_document())
    save(evidence, "source-before", source_hashes(root))
    operator = OWNER / ".kuzushi/v3/config.toml"
    save(evidence, "operator-config-before", {"sha256":hashlib.sha256(operator.read_bytes()).hexdigest()})
    (evidence / "runtime-home.txt").write_text(str(home))


def native(root, evidence, name, tool, value):
    saved = evidence / (name + ".stdout.json")
    if saved.exists():
        receipt = json.loads(saved.read_text())
        assert receipt["status"] == "completed", "Retain the failed receipt and correct preparation explicitly"
        return receipt["data"]
    env = dict(os.environ, HOME=str(FIXTURE / "home"))
    for key in ["NODE_OPTIONS", "KUZUSHI_MODEL", "KUZUSHI_LANGGRAPH_BRIDGE", "KUZUSHI_AGENT_MCPS", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]:
        env.pop(key, None)
    result = subprocess.run([env["KUZUSHI_NATIVE_BIN"], "--plain", "--target", str(root), "run", tool, "--input", json.dumps(value)], cwd=root, env=env, capture_output=True, text=True, timeout=45)
    (evidence / (name + ".stdout.json")).write_text(result.stdout)
    (evidence / (name + ".stderr.txt")).write_text(result.stderr)
    assert result.returncode == 0, (name, result.stderr)
    return json.loads(result.stdout)["data"]


def prepare(root, evidence):
    assert source_hashes(root) == json.loads((evidence / "source-before.json").read_text())
    native(root, evidence, "source-inventory", "context:build", {"enrichment":False})
    context = native(root, evidence, "manual-import", "threat-model:import", {"path":".kuzushi/manual-context.json","activate":False,"label":"Owned invoice source contracts"})["modelRef"]
    native(root, evidence, "manual-map", "campaign:context-map", {"threatModelRef":context})
    draft = native(root, evidence, "scope-draft", "pack:scopes", {})
    accepted = native(root, evidence, "scope-accepted", "pack:scopes", {"operation":"accept","proposalRef":draft["reference"],"acknowledgements":{"inventoryLimitations":True,"exclusions":False,"overlappingDiscovery":False}})
    study = native(root, evidence, "scan-draft", "campaign:study", {"campaignId":CAMPAIGN,"investigationId":INVESTIGATION,"trials":3,"workers":1,
        "scanInput":{"taskMode":"manual","tasks":["agentic"],"model":MODEL,"mode":"whitebox-static","thinkingLevel":"low","mcps":False,"agenticMaxModelTurns":2,"maxInventoryFiles":64,"maxBytesPerFile":4096,"maxFindings":4,"triage":False,"verify":False,"autoPatch":False,"scanScopeRef":{"proposal":accepted["reference"],"scopeId":"repository"},"threatModelRef":context}})
    plan = json.loads((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_text())
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    file_hash = hashlib.sha256((root / ".kuzushi/v3/campaigns" / CAMPAIGN / "plan.json").read_bytes()).hexdigest()
    saved_hash = evidence / "prepared-plan-file-hash.json"
    if saved_hash.exists():
        assert json.loads(saved_hash.read_text()) == file_hash
    else:
        save(evidence, "prepared-plan-file-hash", file_hash)
    approval = {"investigationId":INVESTIGATION,"expectedRevision":0,"model":MODEL,"maxProviderCalls":8,"protectedReviewCalls":2,"reason":"Three fixed source-only discovery jobs with at most six discovery requests; two protected Review calls do not approve Review work.","campaignId":CAMPAIGN,"campaignPlanSha256":study["planSha256"],"campaignJobs":3,"maxJobAttempts":1}
    save(evidence, "proposed-approval-input", approval)
    save(evidence, "prepared-test", {"campaignId":CAMPAIGN,"planSha256":study["planSha256"],"model":MODEL,"reasoning":"low","fixedJobs":3,"workers":1,"attemptsPerJob":1,"newDiscoveryRequestsIncludingRetries":6,"sharedTotalLimit":8,"protectedReviewCalls":2,"reviewWorkApproved":False,"priorLiveRequests":8,"maximumAggregateDiscoveryRequests":14,"dollarCost":"unknown; no strict dollar ceiling","approvalGranted":False,"launched":False,"sourceExecuted":False,"sourceFiles":len(SOURCES),"contextRef":context,"target":str(root)})
    (evidence / "campaign-command.txt").write_text("campaign " + CAMPAIGN)
    verify(root, evidence)


def verify(root, evidence):
    control = FIXTURE / "control"
    assert root == FIXTURE / "target"
    operator = OWNER / ".kuzushi/v3/config.toml"
    assert hashlib.sha256(operator.read_bytes()).hexdigest() == json.loads((control / "operator-config-before.json").read_text())["sha256"]
    assert source_hashes(root) == json.loads((control / "source-before.json").read_text())
    campaign = root / ".kuzushi/v3/campaigns" / CAMPAIGN
    assert not (campaign / "queue.json").exists()
    assert hashlib.sha256((campaign / "plan.json").read_bytes()).hexdigest() == json.loads((control / "prepared-plan-file-hash.json").read_text())
    plan = json.loads((campaign / "plan.json").read_text())
    assert len(plan["jobs"]) == 3 and plan["workers"] == 1
    for job in plan["jobs"]:
        value = job["input"]
        assert value["model"] == MODEL and value["tasks"] == ["agentic"]
        assert value["agenticMaxModelTurns"] == 2 and value["mcps"] is False
        assert all(not value[key] for key in ["triage", "verify", "autoPatch", "patch", "pocExecution", "dynamicAnalysis"])
    assert json.loads((root / ".kuzushi/threat-models/manifest.json").read_text()).get("active") is None
    counts = current_counts(root, evidence)
    assert all(value in [None, 0] for value in counts.values()), counts
    with ledger(root, evidence) as db:
        tables = [row[0] for row in db.execute("select name from sqlite_master where type='table' and name like 'investigation%'")]
        assert all(db.execute('select count(*) from "' + name + '"').fetchone()[0] == 0 for name in tables)
    save(evidence, "unapproved-check", {"sourceFilesUnchanged":len(SOURCES),"queueExists":False,"counts":counts,"approvedAllowanceRows":0,"providerRequests":0,"sourceExecuted":False})


if __name__ == "__main__":
    root, evidence, home = [Path(value).resolve() for value in sys.argv[1:4]]
    if sys.argv[4] == "seed":
        seed(root, evidence, home)
    elif sys.argv[4] == "prepare":
        prepare(root, evidence)
    elif sys.argv[4] == "inspect":
        (evidence / "campaign-command.txt").write_bytes((FIXTURE / "control/campaign-command.txt").read_bytes())
        verify(root, evidence)
    else:
        verify(root, evidence)
