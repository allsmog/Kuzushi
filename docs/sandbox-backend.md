# Sandbox executor backend cookbook

`SandboxExecutor` (in `crates/kuzushi-core/src/executor.rs`) sends commands
to a remote backend over plain HTTP/JSON. This doc describes the
contract a backend has to implement, and sketches reference adapters
for three common targets:

1. Vercel Sandbox microVMs
2. Kubernetes Jobs
3. AWS Batch

The Kuzushi-side wiring is fixed; the only thing that changes between
backends is the small HTTP server in front of them.

---

## Protocol contract

The client (`SandboxExecutor`) makes three request shapes. Endpoints are
relative to the operator's `--executor sandbox:<endpoint>` URL.

### `POST /runs`

Launch a new run. Request body (JSON):

```json
{
  "clientId": "kuzushi-91234",
  "runId": "semgrep-9f8e2c3a-...",
  "command": ["semgrep", "--json", "--config", "p/security-audit", "."],
  "workingDir": "/home/operator/repo",
  "env": {"KEY": "VAL"},
  "stdin": null
}
```

* `clientId` + `runId` form a unique idempotency key. The same
  pair MUST always return the same accepted run; concurrent kuzushi
  processes against the same backend rely on this to not collide.
* `command` is an argv-style array. The backend runs it inside the
  container/microVM/job.
* `workingDir` is the **client-side** absolute path. The backend may
  ignore it (DockerExecutor mounts it; remote backends typically
  expect a tarball upload separate from this call).
* `stdin` is the bytes to feed the process on stdin; `null` if none.

Response body (JSON):

```json
{ "runId": "semgrep-9f8e2c3a-..." }
```

The `runId` echoed back is what the client uses for the subsequent
`/runs/<id>` and `/runs/<id>/status` calls. Most backends will echo the
operator-supplied id; if your backend mints its own, return that.

### `GET /runs/<id>`

Fetch the final result. Response body (JSON):

```json
{
  "status": "succeeded",
  "stdout": "{\"results\":[...]}\n",
  "stderr": "",
  "exitCode": 0
}
```

`status` is one of `pending`, `running`, `succeeded`, `complete`
(synonym for succeeded), `failed`, `error` (synonym for failed),
`cancelled`. Anything else maps to `unknown` on the client.

`exitCode` is optional; when absent, treat status as the source of
truth.

### `GET /runs/<id>/status`

Lightweight status poll. Response body:

```json
{ "status": "running" }
```

The client only calls this when it needs a status without paying for the
full payload — it caches results from `GET /runs/<id>` automatically.

### Authentication

When the operator sets `KUZUSHI_SANDBOX_API_KEY`, every request carries:

```
Authorization: Bearer <key>
Content-Type: application/json
```

The backend should reject requests without the header. The key is
opaque to Kuzushi.

---

## Reference: Vercel Sandbox microVMs

Vercel Sandbox lets you tar up a workspace, ship it to a microVM,
exec a command, and stream results back. A thin shim on a single
serverless function turns that into the `/runs` shape above.

```ts
// pseudocode in vercel/api/runs.ts
import { Sandbox } from "@vercel/sandbox";
import { kv } from "@vercel/kv";

export async function POST(req: Request) {
  const { clientId, runId, command, workingDir, env, stdin } = await req.json();
  const key = `${clientId}/${runId}`;
  if (await kv.exists(key)) return Response.json({ runId });   // idempotent
  await kv.set(key, { status: "pending" });

  // Tarball upload happens separately; the client uploads workingDir
  // to a presigned URL before POSTing /runs in production.
  const sb = await Sandbox.create({ image: "ghcr.io/operator/scanner-base" });
  await sb.writeFiles(/* presigned download */);
  const result = await sb.runCommand({
    cmd: command[0],
    args: command.slice(1),
    cwd: "/workspace",
    env,
    stdin,
  });
  await kv.set(key, {
    status: result.exitCode === 0 ? "succeeded" : "failed",
    stdout: await result.stdout.text(),
    stderr: await result.stderr.text(),
    exitCode: result.exitCode,
  });
  return Response.json({ runId });
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const id = url.pathname.match(/\/runs\/([^/]+)/)?.[1];
  const key = await findClientPrefix(req, id);   // header-based auth
  return Response.json(await kv.get(key));
}
```

The `clientId` lookup is intentional: the auth header is the source of
truth for *which* client's namespace to read. Without that, two
operators on the same kuzushi-cli build and the same `runId` would see
each other's results.

---

## Reference: Kubernetes Jobs

A Kubernetes-Jobs adapter is a small Go HTTP server that creates a
Job per `POST /runs`, names it `<clientId>-<runId>` (so the
namespace is the idempotency key), waits for completion, and stuffs
the logs into a status field.

```go
// pseudocode
func (s *Server) handleRunsPost(w http.ResponseWriter, r *http.Request) {
    var req LaunchRequest
    json.NewDecoder(r.Body).Decode(&req)

    name := fmt.Sprintf("%s-%s", req.ClientID, req.RunID)
    // Idempotent: if Job already exists, return its run id.
    if _, err := s.k8s.BatchV1().Jobs("kuzushi").Get(ctx, name, metav1.GetOptions{}); err == nil {
        json.NewEncoder(w).Encode(LaunchResponse{RunID: req.RunID})
        return
    }

    job := &batchv1.Job{
        ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kuzushi"},
        Spec: batchv1.JobSpec{
            Template: corev1.PodTemplateSpec{
                Spec: corev1.PodSpec{
                    RestartPolicy: corev1.RestartPolicyNever,
                    Containers: []corev1.Container{{
                        Name:    "scanner",
                        Image:   s.image,
                        Command: req.Command,
                        Env:     toEnvVars(req.Env),
                    }},
                },
            },
        },
    }
    s.k8s.BatchV1().Jobs("kuzushi").Create(ctx, job, metav1.CreateOptions{})
    json.NewEncoder(w).Encode(LaunchResponse{RunID: req.RunID})
}
```

The hard part for Kubernetes is workspace upload. Two options:

1. **Tarball + emptyDir initContainer**: each Job has an initContainer
   that fetches a tarball from object storage and unpacks into
   `/workspace`. The client uploads to a presigned URL between
   `POST /runs` and the Job actually starting.
2. **Persistent volume**: a single ReadWriteMany PV that operators
   `rsync` their repo to before `kuzushi scan --executor sandbox:`.

(1) is more flexible; (2) is simpler if your kuzushi instances are all
on the same network as the cluster.

---

## Reference: AWS Batch

AWS Batch is the heaviest of the three but the cheapest at high
fan-out. The shape is the same: a small Lambda or ECS-Fargate task
exposes `/runs`, calls `submitJob` against a pre-defined Batch queue +
job definition, and polls until the job finishes.

The idempotency key maps to `containerOverrides.environment.RUN_ID`;
Batch doesn't dedupe by name, so the adapter has to read DynamoDB
before submitting.

Workspace upload uses S3 + presigned URLs. The container's command
unpacks the tarball, runs the scanner, uploads a result tarball to S3,
and the adapter reads it back when the operator calls `GET /runs/<id>`.

---

## Operator-side workflow

Once a backend is up:

```bash
# Set the credential.
export KUZUSHI_SANDBOX_API_KEY=vck_...

# Run a scan through it.
kuzushi scan --executor sandbox:https://api.example.com/v1 ./repo
```

`kuzushi scan` wires the `SandboxExecutor` into `ToolExecutionContext`,
the SAST tool dispatcher checks `ctx.executor`, and `semgrep:scan` /
`codeql:scan` route through `scan_via_executor` instead of spawning
local subprocesses.

The findings come back via the normal `.kuzushi/v2/findings.sqlite3`
write path. `kuzushi findings` and `kuzushi metrics` work without any
backend awareness.

---

## What's intentionally *not* in the protocol

* **Streaming stdout**: the contract is request/response. Operators
  who want progress-as-it-happens should run with `--executor
  docker:<image>` (the `LocalExecutor` and `DockerExecutor` paths
  honour `Executor::launch_streaming`).
* **Backend-side concurrency caps**: kuzushi's spend ledger
  (`crates/kuzushi-core/src/spend.rs`) handles per-operation budgeting
  on the client side. The backend is responsible for its own queue
  limits.
* **File-output capture**: the protocol assumes `/dev/stdout` is the
  one true output channel. SARIF gets written there via codeql's
  `--output=/dev/stdout`. Tools that insist on writing to a file
  should be wrapped: `sh -c '... && cat output.json'`.

---

## Future work

* A reference adapter implementation in `examples/sandbox-backend/`
  that an operator can `vercel deploy` or `kubectl apply` end-to-end.
* `Operation::SandboxOverhead` budget bucket so the per-call HTTP
  round-trip cost is visible in `kuzushi metrics`.
* Streaming variant — `WebSocket /runs/<id>/stream` — once the protocol
  has shaken out in production.
