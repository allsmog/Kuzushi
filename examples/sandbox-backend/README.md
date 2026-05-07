# Sandbox backend reference adapters

This directory contains two deployable reference implementations of the
Kuzushi `SandboxExecutor` HTTP protocol (see `docs/sandbox-backend.md`):

| Subdir       | Backend               | Deploy via          |
|--------------|-----------------------|---------------------|
| `vercel/`    | Vercel Sandbox microVMs | `vercel deploy`     |
| `k8s/`       | Kubernetes Jobs       | `kubectl apply -f ` |

Both expose the same four endpoints:

* `POST /runs` — launch
* `GET  /runs/<id>` — fetch final result
* `GET  /runs/<id>/status` — lightweight status poll
* `GET  /runs/<id>/output?since=<offset>` — long-poll streaming

Operators point their kuzushi-cli at whichever they deploy:

```bash
export KUZUSHI_SANDBOX_API_KEY=vck_...
kuzushi scan --executor sandbox:https://sandbox.example.com/v1 ./repo
```

See each subdir's `README.md` for backend-specific deployment notes.

---

## Validating an adapter against the real client

The `kuzushi-core` test suite exercises the protocol shape but not a
running backend. To smoke-test a real deployment:

```bash
# 1. Start a tiny scanner image (adjust to your needs).
docker pull returntocorp/semgrep:latest

# 2. Deploy whichever adapter you picked.
cd vercel && vercel deploy
# (or)
cd k8s && kubectl apply -f .

# 3. Run kuzushi against a tiny target.
mkdir -p /tmp/probe && echo 'eval(input())' > /tmp/probe/x.py
KUZUSHI_SANDBOX_API_KEY=$VERCEL_API_KEY \
  kuzushi scan --executor sandbox:https://your-deploy.example.com/v1 /tmp/probe

# 4. Inspect the round-trip cost.
kuzushi metrics --target /tmp/probe --json | jq '.bySpend["sandbox_overhead"]'
```

If it all works you'll see findings in `.kuzushi/v2/findings.sqlite3`
and a non-zero `sandbox_overhead` entry in `kuzushi metrics`.

---

## Protocol invariants the client relies on

These are the contract bits the SandboxExecutor depends on. Adapters
that violate them will produce confusing failures upstream:

1. **Idempotency.** The `(clientId, runId)` pair is the unique key. A
   second `POST /runs` with the same pair MUST return the same
   `runId` without re-running the work.
2. **Auth.** When `Authorization: Bearer <key>` is present, the
   adapter MUST gate access; when absent and `KUZUSHI_SANDBOX_API_KEY`
   is unset, the adapter MAY allow unauthenticated access (e.g. for
   local dev).
3. **Status strings.** The set the client recognises:
   `pending` / `running` / `succeeded` / `complete` / `failed` /
   `error` / `cancelled`. Anything else maps to `unknown`.
4. **Trailing-slash normalisation.** The client strips trailing `/`
   from the endpoint at construction. Adapters MUST accept both.
5. **Streaming offset.** When the long-poll endpoint is implemented,
   `nextOffset` MUST monotonically increase and `done: true` MUST be
   set on the final chunk. The client gives up after ~30s of no
   progress and falls back to one-shot collect.
