# Vercel-Sandbox adapter

> Status: reference adapter only. The current CLI does not yet accept `--executor sandbox:<url>`; this preserves the Vercel protocol sketch for future remote-executor integration.


A four-endpoint adapter for the source-branch remote-executor protocol. It was designed to route scanner runs into Vercel Sandbox microVMs once the CLI supports a `--executor sandbox:<url>` path.

## What's inside

```
vercel/
├── README.md
├── package.json
├── vercel.json
├── api/
│   ├── runs.ts                 # POST /v1/runs
│   ├── runs.[id].ts            # GET  /v1/runs/<id>
│   ├── runs.[id].status.ts     # GET  /v1/runs/<id>/status
│   └── runs.[id].output.ts     # GET  /v1/runs/<id>/output?since=<offset>
└── lib/
    ├── auth.ts                 # Authorization: Bearer <key> check
    ├── kv.ts                   # Vercel KV wrapper for run state
    └── sandbox.ts              # @vercel/sandbox launch helper
```

## Deploy

```bash
# 1. Install deps.
pnpm install

# 2. Set the auth secret.
vercel env add KUZUSHI_SANDBOX_API_KEY

# 3. Deploy.
vercel deploy --prod
```

With the source-branch executor wiring, the operator CLI shape was:

```bash
export KUZUSHI_SANDBOX_API_KEY=$(cat ~/.vercel/secret)
# future executor-capable CLI shape
kuzushi scan --executor sandbox:https://your-deploy.vercel.app/v1 ./repo
```

## Workspace upload

This minimal adapter assumes the scanner image already contains the
target source (e.g. baked-in fixtures for an eval suite). A
production-grade adapter handles workspace upload via a presigned S3
URL between `POST /runs` and the actual `Sandbox.runCommand` call;
see the comments in `api/runs.ts` for the seam.

## What's NOT here

* **Concurrency limits.** Vercel KV doesn't have native counters
  beyond `incr`/`decr`. A real deployment should rate-limit at the
  CDN edge or via `@vercel/kv`'s `set NX EX` for a global gate.
* **Workspace pruning.** Sandbox results are stored in KV with a
  24-hour TTL; long-running operators that want a forensic trail
  should mirror to S3 / R2.
* **Retry on transient sandbox errors.** The adapter returns the raw
  failure to the client; the client will mark the run failed.
