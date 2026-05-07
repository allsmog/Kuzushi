# Kubernetes-Jobs adapter

A small Go HTTP server that turns Kuzushi `SandboxExecutor` requests
into per-run Kubernetes Jobs. Workspace upload is via a presigned
S3/GCS/MinIO URL (paste an `s3://...` or use the operator's local
storage class — the adapter is agnostic).

## What's inside

```
k8s/
├── README.md
├── manifest.yaml          # Deployment + Service + RBAC for the adapter
├── adapter/
│   ├── main.go            # http.ServeMux with the four endpoints
│   ├── jobs.go            # k8s Job creation + status mapping
│   ├── auth.go            # Authorization: Bearer <KUZUSHI_SANDBOX_API_KEY>
│   └── go.mod
└── runner/
    └── Dockerfile          # Container image used by the spawned Jobs
                             # (semgrep / codeql / etc.)
```

## Deploy

```bash
# 1. Build + push the runner image (scanner toolchain).
docker build -t ghcr.io/<you>/kuzushi-runner:latest -f runner/Dockerfile runner/
docker push ghcr.io/<you>/kuzushi-runner:latest

# 2. Build + push the adapter image.
docker build -t ghcr.io/<you>/kuzushi-sandbox-adapter:latest adapter/
docker push ghcr.io/<you>/kuzushi-sandbox-adapter:latest

# 3. Set the auth secret + apply manifests.
kubectl create secret generic kuzushi-sandbox \
  --from-literal=KUZUSHI_SANDBOX_API_KEY=$(openssl rand -hex 32)
kubectl apply -f manifest.yaml

# 4. Expose the Service (Ingress, port-forward, whatever).
kubectl port-forward svc/kuzushi-sandbox-adapter 8080:80
```

Operator-side:

```bash
export KUZUSHI_SANDBOX_API_KEY=<the-secret-from-step-3>
kuzushi scan --executor sandbox:http://localhost:8080/v1 ./repo
```

## Idempotency

Job names are derived as `kuzushi-<clientId>-<runId>` (RFC 1123
sanitised — alphanumeric + hyphen, ≤63 chars). A second `POST /runs`
with the same body finds the existing Job via `kubectl get` and
returns its run id without creating a duplicate.

## Workspace upload

The adapter expects each `POST /runs` body to include a `workingDir`
that's already accessible to the Pod (e.g. an S3 URL the Job's
init-container will fetch). For simpler dev:

```bash
# Dev shortcut: bind-mount a local repo into the cluster via hostPath.
kubectl apply -f manifest.yaml
# (The default manifest mounts ${HOME}/kuzushi-workspaces:/workspace.)
```

For production:

* Use an S3/GCS bucket; the adapter generates a presigned URL the Job
  fetches via an init-container.
* Or use a ReadWriteMany PVC the operators rsync to before scanning.

The choice is yours; the adapter's HTTP contract doesn't care.

## What's NOT here

* **Multi-tenancy.** A single auth key gates the whole namespace. For
  per-team isolation, swap the bearer-token check for an OIDC JWT
  validator and use the `sub` claim as the `clientId`.
* **Long-running streaming.** `GET /runs/<id>/output` returns the
  Pod's stdout/stderr from `kubectl logs --since-time` over each
  poll. For a deployment with >100 concurrent runs, replace with a
  Loki/Promtail tail or a sidecar that streams to an in-memory ring
  buffer.
* **Cleanup.** Completed Jobs aren't garbage-collected. Add
  `ttlSecondsAfterFinished: 86400` to the JobSpec, or run a
  CronJob that prunes old runs from KV/etcd.
