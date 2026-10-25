# EBOOT campaign preparation

`scripts/decomp_campaign.py` provides a local SQLite queue and two isolated
OpenCode workers. It does not alter `scripts/match_function.py`, the matcher
package, or certified sources. `config/decomp_campaign.toml` holds the exact
model allowlist and operational limits; the ignored
`config/decomp_campaign.local.toml` holds this machine's Ghidra paths. The
reviewed 20-entry inventory preserves the 8 EBOOT / 206-instruction and 16 PRX /
912-instruction baselines. Eight entries have known exact Ghidra boundaries;
twelve remain inventory-only until a fresh Ghidra run proves their boundary.

## Safe preparation and status

Run from the repository root in PowerShell. These commands do not start model
sessions:

```powershell
py -3.12 scripts/decomp_campaign.py doctor
py -3.12 scripts/decomp_campaign.py plan
py -3.12 scripts/decomp_campaign.py init
py -3.12 scripts/decomp_campaign.py status
```

`init` is idempotent and writes only the ignored local database at
`build/decomp-campaign/campaign.sqlite3`. `status` reports state counts,
MATCHED functions/instructions, C sources whose hashes still match a verified
checkpoint, blockers, provider attempts, and whether token/cost totals were
available. No OpenAI or DeepSeek inference was made during SETO-DECOMP-039;
provider attempt and token/cost consumption therefore remain zero/not
observable, respectively.

`doctor` checks OpenCode version/catalog/auth, AIMemory MCP, WSL Python, Ghidra,
MWCC, and wibo without invoking a model. Current machine findings:

| Capability | Result |
|---|---|
| OpenCode | READY — 2.1.4; both exact model IDs appear in the catalog |
| AIMemory | READY — 3.1.1 MCP connected in the main checkout and a disposable worker worktree |
| WSL2 Python | READY — Python 3.12.3 |
| Ghidra | READY — 12.1.3; WSL has no Java, so the installed Windows `analyzeHeadless.bat` launcher and Corretto 25 are used |
| MWCC / wibo | READY — MWCC PSP 3.0.1 build 219 and wibo 1.2.0 in the local WSL profile |
| OpenAI model | Catalog available; OpenAI auth is stored. No inference/cost check was made |
| DeepSeek Free | Exact model is in the catalog; provider auth is not listed and execution is unverified |
| Campaign | **BLOCKED by design** — `enabled`, `provider_access_verified`, and `worker_permissions_reviewed` are false |

The repository does not copy or edit the existing global OpenCode/AIMemory
configuration. Worktree preflight rechecks `ai-memory connected` separately
before a future run. No credentials, media, or dumps are written to AIMemory or
campaign logs. Shared memory is retrieval-only for workers; per-function C and
matcher checkpoints remain local. The existing project OpenCode permission
configuration is also left untouched; unattended worker permissions must be
reviewed before setting `worker_permissions_reviewed = true`.

## A future, separately authorized run

SETO-DECOMP-039 did **not** run this command. Do not enable execution until a
later operator explicitly authorizes provider usage, verifies DeepSeek Free
access/cost semantics, and reviews the local settings. The configured workers
are exactly:

* `openai/gpt-6-luna` via provider `openai` (potentially billable; opt-in flag required)
* `opencode/deepseek-v4.1-flash-free` via provider `opencode` (catalog-listed Free model; execution not yet proven)

After that separate authorization/readiness check only, review unattended
worker tool permissions, set `execution.enabled = true`,
`execution.provider_access_verified = true`, and
`execution.worker_permissions_reviewed = true` in the config, then invoke with
all confirmations:

```powershell
py -3.12 scripts/decomp_campaign.py run --continuous --confirm --allow-openai-usage --allow-free-model-usage --max-tasks 40
```

The launcher refuses to run without the config gates, both explicit usage
confirmations, model allowlist/catalog checks, stored OpenAI auth, connected
AIMemory in each worker worktree, and a READY local toolchain. It never selects
an unlisted model as fallback. `opencode run` has no `--dir` in the installed
CLI; each process uses its worker worktree as `cwd` and passes the model,
JSON format, and session explicitly. Continuous mode is still bounded by both
`max_tasks` and `max_duration_seconds`; it exits on an idle queue and never
polls indefinitely. Without `--continuous`, the default run processes at most
one worker wave; an explicit `--max-tasks` remains capped by configuration.

## Monitor, stop, and resume

Run these from another PowerShell window while a future campaign is active:

```powershell
py -3.12 scripts/decomp_campaign.py status
py -3.12 scripts/decomp_campaign.py stop
```

`stop` requests graceful termination and preserves SQLite state. After a normal
stop, or after fixing a blocked provider/auth/toolchain condition:

```powershell
py -3.12 scripts/decomp_campaign.py resume
```

After an unexpected process/host exit, recover only expired leases before
resuming:

```powershell
py -3.12 scripts/decomp_campaign.py resume --recover-expired
```

Use `--retry-blocked` only after diagnosing and fixing the underlying cause;
`resume` explicitly reactivates quota-suspended providers, so it should not be
used as an automatic retry loop. Rate limits honor `Retry-After`, provider
outages back off, and a run exits instead of polling when no worker can claim a
task.

## Session and campaign limits

Before a worker prompt, the runner creates a session through OpenCode's session
API in that worker's worktree and persists the returned session ID. It checks a
saved ID before reuse; a missing session or a provider change gets a new,
independent session. SQLite checkpoints and earlier attempt/session IDs remain
available across that change. Session setup itself does not send a model prompt.

The campaign does not consolidate worker worktrees or automatically promote
MATCHED sources into the certified source tree. Reviewing and consolidating
those sources, then preparing the post-campaign PR, remain manual operator
steps. AIMemory is used only for read-only knowledge retrieval; shared writes
and checkpoint recording remain disabled.

## Verification and isolation

Each worker gets its own ignored Git worktree and branch. The orchestrator
copies the hash-checked EBOOT, importing PRXs, export/import triage report, and
machine-local tool configs into that worktree. Each task gets separate Ghidra
projects, evidence, and matcher output under its worker's `build/` subtree.
Traversal, symlinks, unexpected file edits, and changes to the production
matcher, toolchain config, or private inputs block that attempt.

Every task revalidates the export/NID/call references and obtains a fresh exact
Ghidra function body before model execution. An unverified inventory item first
gets a boundary-only pass. Candidate sources are snapshotted content-addressably
under the ignored campaign build directory; retries restore the best verified
source and preserve its hash. Completion requires two independent full MWCC +
production-matcher results, equal object hashes, exact symbol/size, zero
differences, resolved relocations, and no invalidating limitations. An agent's
own MATCHED claim is never accepted.

Validation performed for preparation (no model inference):

```powershell
py -3.12 -m pytest -q tests/test_decomp_campaign.py
py -3.12 -m compileall -q scripts tests
git diff --check
```

The real-toolchain smoke used the already certified `0x38DB4` source solely to
exercise Ghidra, two isolated MWCC builds, the unchanged production matcher,
and SQLite completion. It returned 63/63 words twice with identical object
hashes; it is not new campaign progress. The WSL integration regression for
SETO-DECOMP-038 passed.

SETO-DECOMP-039-R2 validation (2026-10-25), with campaign execution still
disabled and no model inference:

- OpenCode 2.1.4 session protocol: created via `POST /api/session`, read back
  via `GET /api/session/{id}`, then deleted; no prompt was sent. A direct
  `run --session` continuation was not exercised because that requires a model
  request; the installed CLI help and V2 docs identify `--session` as the
  continuation interface.
- Orchestrator tests: 29 passed; full suite: 864 passed, 44 skipped.
- `compileall` and `git diff --check`: clean.
- Fresh Ghidra proof for `0x38DB4`: 63 contiguous 4-byte instructions; two
  independent MWCC/production-matcher builds returned 63/63 with identical
  object SHA-256 `81b5ac578ed3b4ee12f4c448f0f9f3d0b6b5d3e28b0803a1f8d4457942dc5924`.
  This only rechecked an already certified source and is not campaign progress.
