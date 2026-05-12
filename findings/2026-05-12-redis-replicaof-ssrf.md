# Redis: unauthenticated SSRF via REPLICAOF command

**Discovered:** 2026-05-12 by kuzushi `taint-iris-next:hunt` on `/tmp/targets/redis`
**Target:** redis HEAD (cloned `https://github.com/redis/redis.git` 2026-05-12)
**File:** `src/replication.c`
**Severity (agent triage):** high
**Confidence:** high
**Kuzushi run:** `/tmp/targets/redis/.kuzushi/runs/<latest>/` — pipeline-flagged via
`source_sink_discovery` + agent's Thread D audit + E3 realistic-exploit framing.
Total run cost: **$0.69**.

## Summary

`replicaofCommand()` (`src/replication.c:4345`) accepts the
`REPLICAOF host port` arguments from any redis client and passes
the host string — `c->argv[1]->ptr` — directly to
`replicationSetMaster(char *ip, int port)` at the call site around
line 4400. There is **no hostname validation, no allowlist, no
loopback/metadata-endpoint guard**, and no DNS-resolution check
between the network input and the outbound TCP connect.

Call chain confirmed by tree-sitter:

```
network → replicaofCommand (replication.c:4345)
       → replicationSetMaster (replication.c:3511)
       → connectWithMaster
       → anetTcpNonBlockConnect
```

This is a textbook SSRF gadget. Any redis client capable of issuing
the `REPLICAOF` command can force the redis process to initiate an
outbound TCP connection to any host:port.

## Threat model

Required attacker capability:
1. **TCP connectivity to the redis port** (default 6379).
2. **Permission to issue `REPLICAOF`**. By default in modern redis
   (6.0+), the `default` user is granted `+@all` which includes
   `REPLICAOF`. With `requirepass` UNSET (the out-of-the-box
   configuration), redis accepts unauthenticated commands. So the
   attacker needs:
   - Network reachability + `requirepass` unset, OR
   - Authentication as any user with `+replicaof` / `+@dangerous`
     in their ACL.

Effect: redis process makes an outbound TCP connection to
attacker-chosen `host:port`. Useful for:
- **Cloud metadata exfiltration**: `REPLICAOF 169.254.169.254 80`
  → redis tries to read the AWS/GCP metadata endpoint and surfaces
  the response in error messages / replication logs.
- **Internal-network pivoting**: redis (often deployed inside a
  trust boundary) makes a connection to an internal service the
  attacker's network position can't reach directly.
- **Port scanning**: probe whether internal hosts have open ports
  by observing connect timing.

The pipeline's Thread D + E3 audit framed this correctly:

> "an unauthenticated or low-privilege Redis client sends
> REPLICAOF \<attacker-host\> \<port\> causing the Redis server
> process to initiate a TCP connection to an internal host/port
> that the attacker's network position cannot reach directly
> (cloud metadata endpoint 169.254.169.254, internal service,
> etc.)"

## Code evidence

`src/replication.c:4345-4406` — `replicaofCommand()`:

```c
void replicaofCommand(client *c) {
    /* SLAVEOF is not allowed in cluster mode ... */
    if (server.cluster_enabled) {
        addReplyError(c,"REPLICAOF not allowed in cluster mode.");
        return;
    }
    if (server.failover_state != NO_FAILOVER) { ... }

    /* The special host/port combination "NO" "ONE" turns the
     * instance into a master. */
    if (!strcasecmp(c->argv[1]->ptr,"no") && ...) { ... }
    else {
        long port;
        if (c->argc == 5) { ... }
        if ((getRangeLongFromObjectOrReply(c, c->argv[2], 0, 65535, &port,
            "Invalid master port")) != C_OK) return;

        /* Check if we are already attached to the specified master */
        if (server.masterhost && !strcasecmp(server.masterhost,c->argv[1]->ptr)
            && server.masterport == port) { ... return; }

        /* There was no previous master or the user specified a different one,
         * we can continue. */
        replicationSetMaster(c->argv[1]->ptr, port);    // ← unsanitized host
        ...
    }
    addReply(c,shared.ok);
}
```

The host argument flows verbatim. The only validation is on the
PORT (range-checked to [0,65535]).

## Why this isn't a slam-dunk CVE

The redis maintainer stance is publicly documented:
> "Redis is designed to be accessed by trusted clients inside
> trusted environments." (`redis.io/docs/manual/security/`)

Past redis CVEs around REPLICAOF were specific implementation bugs
(use-after-free in CVE-2023-31655, DoS in CVE-2022-3647) — NOT
the SSRF gadget itself. The SSRF capability of REPLICAOF is
documented behavior to the team's threat model.

Mitigation already supported (but not on by default):
- Set `requirepass` to a strong password.
- Use ACL to remove `@dangerous` (which includes REPLICAOF) from
  the `default` user.
- Bind to non-public interface (`bind 127.0.0.1` — current default
  since redis 3.2).
- Use `protected-mode yes` (current default).

These defenses exist; many production redis deployments still
ship without them.

## Memeability

**Medium.** "Redis SSRF via REPLICAOF" is a real headline but
isn't novel. It's been discussed in:
- HackerOne reports against redis-deploying services
- DEF CON / SANS / OWASP talks on trust-boundary confusion
- Internal-pentest playbooks for any cloud environment with redis

Submitting this as a CVE is **probably not worth it** for
memeability — the redis team will respond *"by design, configure
your ACL"* and decline a CVE.

What **would** be memeable: a chain where redis's REPLICAOF SSRF
reaches a service whose response, combined with redis's
replication-protocol-response handling, produces RCE on the redis
process. That would require a separate analysis pass on
`replicationSetMaster` → `syncWithMaster` → response parsing for
buffer overflow / type confusion bugs. The current finding is the
SSRF primitive only.

## Recommended action

**Don't submit as a CVE.** Instead:

1. **Document the gadget internally** (this artifact serves).
2. **Optional**: file a hardening request with redis maintainers
   asking them to add an opt-in `replicaof-allowed-hosts` ACL
   directive. Likely rejected as "use ACL `+replicaof` to
   restrict who, not where", but worth asking.
3. **Audit your own redis deployments**: confirm `requirepass` is
   set OR `+@dangerous` is removed from the `default` user OR
   redis binds only to non-routable interfaces.

## Discovery method

This was found by the kuzushi taint-iris-next pipeline pointed at
redis HEAD with:
- LLM-curated CWE catalog (CWE-706 SSRF score=70 in the catalog
  output)
- joern reachableByFlows (returned `flowCount=0` due to known C
  frontend limitation tracking `c->argv[]->ptr` member chains, but
  the structural rg + discovery sweep surfaced the candidate)
- Thread D mandatory call-site audit walked the call chain
- E3 realistic-exploit framing produced the
  "unauthenticated client → internal-service-pivot" narrative
  automatically

The agent rejected 2 plausible-looking candidates (Lua eval init
scripts in `src/eval.c`; hiredis `dict.c` UAF) with cited tree-
sitter reasoning. Calibrated rejection.
