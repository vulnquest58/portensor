# ADR 0002: Durable distributed coordinator

- Status: Accepted for v0.10
- Date: 2026-11-19
- Related: [validation baseline](../validation-baseline.md)

## Context

The v0.7.0 coordinator keeps jobs, leases, results, and the merged report in
memory. The P2 lab demonstrates the consequences:

- restart after a claim forgets the lease and resets the shard to pending;
- restart after a result forgets completed work;
- restart after completion starts a fresh run and returns 409 for the report;
- a stale result can be accepted for a pending job;
- a long shard leaves other workers idle under FIFO assignment.

The coordinator must survive process restarts without re-running completed
shards, losing accepted results, or publishing a partial merge. It must also
make duplicate submissions safe and provide operational visibility.

## Decision

### 1. Durable state and locking

The coordinator owns a versioned state file next to the merged report:

- default: `<out>.state.json`;
- optional: `--state FILE` for explicit placement;
- lock: `<state>.lock` or equivalent OS advisory lock held for the coordinator
  lifetime;
- result objects: `<state>.d/<job-id>-<sha256>.json`;
- merged report: the `--out` path, written atomically.

Only one coordinator may own a state/output pair. Startup acquires the lock
before reading or repairing state. A stale lock is removed only after the
platform can prove the recorded owner is not alive; otherwise startup fails
with a clear error.

State directories are created with owner-only permissions (`0700` directories,
`0600` files). Tokens are never persisted. Reports can contain scan data and
receive the same permissions as the merged report.

### 2. State schema

The state file is versioned JSON with a single writer protected by the
coordinator mutex. It stores:

```json
{
  "schema_version": 1,
  "coordinator_id": "uuid-like-id",
  "run_id": "uuid-like-id",
  "restart_count": 0,
  "finishing": false,
  "complete": false,
  "jobs": [
    {
      "id": 0,
      "shard_index": 0,
      "shard_count": 8,
      "args_digest": "sha256:...",
      "status": "pending|running|done|failed",
      "worker": null,
      "lease_expires_unix_ms": null,
      "attempts": 0,
      "result_digest": null,
      "result_path": null,
      "error": null
    }
  ],
  "report": {
    "path": "/path/to/report.json",
    "digest": "sha256:...",
    "ready": false
  }
}
```

Job command arguments are identified by a digest. The full arguments are
reconstructed from the original `--` scan template on startup; the digest
detects an incompatible restart (different template or shard count) and is
rejected before work continues. The state does not contain script payloads,
banners, reports, or tokens.

### 3. Atomic transitions

Every transition is persisted before its HTTP response:

1. **Claim**: validate a pending job, set `running`, store worker and
   `lease_expires_unix_ms`, increment attempts, atomically replace state, then
   return the assignment. A crash before replacement leaves the job pending; a
   crash after replacement leaves a lease that expires normally.
2. **Result**:
   - validate the report against the existing report contract;
   - write it to a temporary file, fsync it, rename it to the content-addressed
     result path, fsync the directory;
   - atomically update the job to `done`, record the digest/path, then return
     accepted.
   - Duplicate submission with the same digest is a no-op success. A different
     digest for a done job is a conflict and is never merged.
   - A crash after the result file is durable but before state replacement is
     repaired at startup by attaching orphan results to their job.
3. **Failure/lease expiry**: increment attempts or mark failed, persist, then
   wake waiters. Expiry uses wall-clock Unix milliseconds, not `Instant`.
4. **Merge**: persist `finishing=true`; merge only done report files in stable
   job order; write the merged report to a temporary file, fsync, rename, then
   persist `complete=true` and the report digest. A crash before `complete`
   leaves `finishing=true`, and startup re-runs the merge.
5. **Completion**: only after the merged report is durable may the coordinator
   answer `/v1/report` with 200. `complete=true` without a valid report is a
   startup repair condition, not a successful state.

State replacement uses a same-directory temporary file, file fsync, atomic
rename, and parent-directory fsync where supported. The state is never edited
in place. A failed fsync/rename aborts the transition and returns an error;
the coordinator does not acknowledge uncommitted work.

### 4. Startup recovery

Before binding the HTTP listener or accepting claims:

1. acquire the lock;
2. load and validate the state schema;
3. verify the job template digest and shard count;
4. inspect the result directory for orphan result files; validate and attach
   them to matching non-done jobs;
5. restore leases using wall-clock deadlines; leave unexpired leases running,
   and requeue expired leases subject to attempt limits;
6. if `finishing` is set, re-run the merge from durable results;
7. if `complete` is set, verify the report exists and matches its digest;
   otherwise re-merge or fail closed;
8. increment `restart_count`, persist, and only then mark readiness true.

Recovery is idempotent and may itself be interrupted. A second restart must
reach the same state and report digest for identical results.

`/readyz` returns 200 only after recovery completes and the lock is held.
Before readiness, `/v1/claim` and `/v1/result` return 503. `/metrics` may be
available after recovery only.

### 5. Idempotency and exactness

The coordinator guarantees **exactly-once accepted completion**, not exactly
once execution of network probes. A worker may execute a shard again after a
lease expiry; the result is accepted only if it is the first valid completion
or an identical duplicate. The merged report contains one result per job id.

Workers use `(run_id, job_id, result_digest)` as the idempotency key. A worker
that restarts must query status before retrying a result whose response was
lost. The coordinator never accepts a different report for a completed job.

The report merge is deterministic: sort by job id, validate every report,
deduplicate identical findings, and preserve the existing merge contract. A
test compares a post-restart merged report with an uninterrupted run using the
same input reports.

### 6. Work units and load balancing

The durable job record is the source of truth for shards. To meet the v0.10
load-balance gate, v0.10 may split a running job into child work units. The
state schema reserves `parent_job_id` and `unit` fields so a split can be
journaled before it is announced. Splitting must preserve deterministic
coverage and must be idempotent: a duplicated split request returns the
existing child identifiers. P3 freezes the state and recovery rules; the
split policy itself is implemented with the v0.10 scheduler and tested by the
uneven-load lab.

Until splitting lands, the coordinator must not claim the 5-second idle gate
is satisfied. The current P2 baseline records the failure.

### 7. Metrics and diagnostics

Authenticated endpoints expose:

- `/readyz`: recovery complete, lock held;
- `/metrics`: queue depth, running jobs, completions, failures, active leases,
  expired leases, duplicate results, merge failures, restart count, and
  in-flight requests.

`/v1/status` includes the same counters in JSON plus per-worker lease state.
Logs correlate `run_id`, `job_id`, `worker_id`, `attempt`, and transition
outcome. Tokens, report contents, payloads, and banners are never logged.

### 8. Push mode and shutdown

Push agents use the same claim/result protocol with the same idempotency key.
On coordinator shutdown, stop accepting claims, persist all acknowledged state,
and leave leases intact. A graceful shutdown does not mark a run complete.
SIGKILL and process crashes follow the recovery path. If the report is not
durable, `/v1/report` must not return 200.

## Failure-injection matrix

The v0.10 tests must inject a crash or transport failure at each point and
restart the coordinator:

| Injection point | Required recovery | Assertion |
|---|---|---|
| Before any claim | Jobs remain pending | Restart status matches the pre-crash pending set |
| After claim persisted, before response | Lease restored | No immediate duplicate assignment; lease expires or heartbeats continue |
| After claim response, mid-scan | Lease restored or requeued | Attempt count is bounded and no shard is lost |
| Mid-result HTTP body | No durable result | Job remains leased; worker retry succeeds |
| After result file fsync, before state update | Orphan result attached | Completed job appears once; report includes it |
| After state update, before response | Duplicate result is idempotent | Same digest returns success; different digest conflicts |
| During merge | `finishing` persisted | Restart re-merges and produces the same semantic report |
| After merged report write, before complete state | Merge repaired | Report digest matches and `/v1/report` becomes available |
| After complete state | Completion survives | Repeated restart returns the same report and no new work |
| Duplicate/stale worker result | No double completion | Done job is unchanged; conflict is recorded |
| Lease expiry and retry | Bounded attempts | Exactly one accepted result per job |
| Four-worker uneven load | No idle >5 s while work remains | Completion <= 1.2x lower bound; work units split or are reassigned |

## Consequences

- The coordinator gains a local durability dependency and must handle disk
  errors explicitly; it cannot claim completion after a failed fsync.
- State files and result objects add disk usage; the state is bounded by shard
  count and results are removed only after a completed report is verified.
- Restarts are safe but may re-execute in-flight scans after lease expiry;
  probes must remain safe for the configured scope.
- The design is single-coordinator. Multi-coordinator consensus is out of scope;
  use one durable owner and workers/agents for scale.
- The v0.10 implementation must add crash-injection tests and verify the report
  equivalence assertion, not merely check that the process restarts.

## Alternatives considered

1. **Keep state in memory and rely on workers retrying.** Rejected: completed
   results and the report cannot be recovered, and the P2 lab shows lost
   progress.
2. **SQLite for jobs and results.** Viable, but adds a database dependency and
   migration surface. The state is small and single-writer; a versioned atomic
   JSON snapshot is sufficient and easier to audit for this release.
3. **Append-only event log with periodic snapshots.** More efficient at high
   shard counts, but recovery and compaction add complexity. The snapshot model
   can be upgraded with an internal journal if state size becomes material.
4. **Exactly-once probe execution.** Rejected: impossible to guarantee across
   process crashes and network timeouts without transactional targets. The
   contract is exactly-once accepted completion with idempotent workers.
