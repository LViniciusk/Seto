# EBOOT campaign execution, verification and integration

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
available. No OpenAI or DeepSeek inference was made in SETO-DECOMP-039 or 040;
the 040 database has zero attempts and no measurable token/cost usage.

`doctor` checks OpenCode version/catalog/auth/model metadata, AIMemory MCP, WSL
Python, Ghidra, MWCC, and wibo without invoking a model. Current machine
findings:

| Capability | Result |
|---|---|
| OpenCode | READY — 2.1.4; both exact model IDs appear in the catalog |
| AIMemory | READY — 3.1.1 MCP connected in the main checkout and a disposable worker worktree |
| WSL2 Python | READY — Python 3.12.3 |
| Ghidra | READY — 12.1.3; WSL has no Java, so the installed Windows `analyzeHeadless.bat` launcher and Corretto 25 are used |
| MWCC / wibo | READY — MWCC PSP 3.0.1 build 219 and wibo 1.2.0 in the local WSL profile |
| OpenAI model | Catalog available and auth is stored, but the auth mode is unknown. GPT-6 Luna can be billable; included subscription usage is not verified, so **BLOCKED** |
| DeepSeek Free | **READY in the ignored R3 pilot profile** — exact model metadata proves `apiKey=public`, active/enabled status, and zero input/output/cache cost; operator access was independently confirmed |
| Worker agent | `seto-decomp-worker` is discovered and its effective policy is restricted in both checkout and campaign worktree: shell/external paths denied; edits limited to candidate C and campaign build paths; AIMemory query/read only |
| Campaign | Pilot prepared but **not started**. Versioned defaults remain disabled; only the local R3 profile enables the verified Free worker and still requires explicit `run --confirm` |

OpenCode's [provider guide](https://opencode.ai/v2/docs/providers) distinguishes
ChatGPT-plan sign-in from API-key usage; its [Console model guide](https://opencode.ai/v2/docs/console/models)
says pay-as-you-go requests are charged. The local `auth list` only says
`OpenAI stored`, so neither route is inferred here. The
[model catalog](https://opencode.ai/v2/docs/models) listing is not treated as
proof that this project can execute the DeepSeek Free model.

The repository does not copy or edit the existing global OpenCode/AIMemory
configuration. The broad legacy project default is overridden for campaign
sessions by `.opencode/agents/seto-decomp-worker.md`; `doctor` inspects OpenCode's
effective agent rules rather than trusting that file alone. The R3 review
checked the effective rules in both the checkout and actual campaign worktree.
Workers have no shell, subagent, or external-directory permission and can edit only candidate
sources/campaign artifacts. Worktree preflight rechecks AIMemory connectivity.
Workers may query/read AIMemory but may not write or message it. No credentials,
media, or dumps are recorded in AIMemory or the campaign ledger.

## A future, separately authorized run

SETO-DECOMP-040 made **zero model requests**. Stored authentication alone does
not make OpenAI READY; DeepSeek's catalog entry alone does not prove access.
The R3 preflight accepts the exact DeepSeek Free model only when current
`/api/model` metadata proves public auth, active/enabled state and zero cost,
and the operator has separately verified access. The configured workers are:

* `openai/gpt-6-luna` via provider `openai` (requires proven subscription-included usage; API-key/billable mode is rejected)
* `opencode/deepseek-v4.1-flash-free` via provider `opencode` (requires exact public model metadata, verified access, and exact Free usage)

After that evidence exists, set only the corresponding worker's
`usage_mode` (`subscription_included` for OpenAI or `free` for the exact
DeepSeek model) and `access_verified = true`. Then explicitly review the
effective agent policy and set `execution.enabled`,
`execution.provider_access_verified`, and `execution.worker_permissions_reviewed`
to true. The ordinary `run` command is the **pilot**: it is restricted to
`0x2C28C` and `0x4217C`, max 4 total attempts with two READY providers (max 2
with only one), and a 30-minute deadline. Pass only the confirmation flag(s) for
the READY worker(s):

```powershell
py -3.12 scripts/decomp_campaign.py run --confirm --allow-openai-usage --allow-free-model-usage --max-tasks 4
```

The launcher selects **only** workers that pass catalog, auth, exact cost-mode,
explicit access-verification, and effective permission checks. A blocked worker
is omitted; it is never selected as an automatic paid fallback. `opencode run`
uses each isolated worktree as `cwd` and passes the model, restricted agent,
JSON format, and session explicitly. No model process starts from `doctor`,
`plan`, or `status`.

Only after reviewing a valid pilot and separately authorizing expansion may an
operator set `execution.pilot_verified`,
`execution.productive_expansion_authorized`, and `execution.continuous` true,
then opt into the bounded 20–40-attempt campaign (the configured ceiling is 40
and 2 hours):

```powershell
py -3.12 scripts/decomp_campaign.py run --productive --continuous --confirm --allow-openai-usage --allow-free-model-usage --max-tasks 40
```

Usage flags are conditional: omit `--allow-openai-usage` unless OpenAI is READY;
omit `--allow-free-model-usage` unless the exact Free worker is READY. A single
READY provider can run independently. Productive mode is blocked until both the
pilot review and separate expansion authorization are recorded.

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
API in that worker's worktree, binding the restricted agent and exact model, and
persists the returned session ID. It checks the saved ID, location, agent, and
model before reuse; a missing/mismatched session or provider change gets a new,
independent session. SQLite checkpoints and earlier attempt/session IDs remain
available across that change. Session setup itself does not send a model prompt.

Workers never promote sources. After a task is `matched`, inspect its checkpoint
and run a fresh integration gate for only that address:

```powershell
py -3.12 scripts/decomp_campaign.py promote --address 0x2c28c
```

`promote` requires a hash-verified best-source snapshot, two strict stored
reports, campaign worker/session provenance, an intact exact Ghidra log, current
EBOOT/export evidence, and no conflicting certified source. It then runs the
production MWCC/matcher twice again, requires complete deterministic MATCHED
reports, copies only that source without overwriting conflicts, and records
address/session/source/build hashes in `docs/decomp-progress.md`. NONMATCHING,
INCONCLUSIVE, incomplete, or corrupt candidates stay in checkpoints/build only.
Promotion does not commit or merge anything.

## Verification and isolation

Each worker gets its own ignored Git worktree and branch. The orchestrator
copies the hash-checked EBOOT, importing PRXs, export/import triage report, and
machine-local tool configs into that worktree. Each task gets separate Ghidra
projects, evidence, and matcher output under its worker's `build/` subtree. A
prior Ghidra log is reused only when the address/worker path, exact boundary,
EBOOT/export preflight, and recorded SHA-256 all still validate.
Traversal, symlinks, unexpected file edits, and changes to the production
matcher, toolchain config, or private inputs block that attempt.

Every task revalidates export/NID/call references and obtains a fresh exact
Ghidra body, or reuses only hash-checked exact evidence tied to the same EBOOT,
worker and address. An unverified inventory item first gets a boundary-only
pass. Candidate sources are snapshotted content-addressably
under the ignored campaign build directory; retries restore the best verified
source and preserve its hash. Completion requires two independent full MWCC +
production-matcher results, equal object hashes, exact symbol/size, zero
differences, resolved relocations, and no invalidating limitations. An agent's
own MATCHED claim is never accepted.

SETO-DECOMP-039 preparation validation (no model inference):

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

SETO-DECOMP-040 status before R3 (2026-10-25), no model inference:

- OpenAI: **BLOCKED** — catalog available/auth stored, but stored auth does not
  identify a subscription-included route; additional cost cannot be excluded.
- DeepSeek Free was then **BLOCKED** — the earlier preflight required a stored
  auth-list entry and did not consume `/api/model` metadata. R3 supersedes this
  readiness result for the exact public Free model.
- Worker policy: effective OpenCode rules audited; shell, external directories,
  broad edits and subagents denied. AIMemory access is query/read only.
- Pilot defaults: targets `0x2C28C` + `0x4217C`, up to 4 attempts / 30 minutes;
  one READY worker is capped at 2 attempts. Productive expansion requires a
  successful reviewed pilot and an independent config authorization.
- Promotion command and corruption/conflict guards are implemented; no new
  source qualified for promotion in this blocked run.
- Test and real-toolchain results are recorded in the 040 section of
  `docs/decomp-progress.md`.

## SETO-DECOMP-040-R3 — DeepSeek Free pilot readiness (2026-10-25)

- `_opencode_preflight()` reads JSON from `opencode api get /api/model` and
  accepts public auth only for the exact allowlisted
  `opencode/deepseek-v4.1-flash-free` entry. It requires one unambiguous
  metadata record, `settings.apiKey="public"`, `status="active"`,
  `enabled=true`, and complete zero-valued input/output/cache pricing. Missing,
  malformed, contradictory or nonzero metadata remains BLOCKED. OpenAI retains
  its stored-auth and explicit subscription-included cost checks.
- Local `doctor` result: DeepSeek Free **READY** with public metadata and
  `usage_mode=free`; OpenAI **BLOCKED** (`usage_mode=unknown`, access unverified,
  additional cost not excluded). The effective restricted worker policy and
  AIMemory MCP passed in both checkout and campaign worktree. AIMemory 3.1.1,
  WSL Python 3.12.3, Ghidra, MWCC and wibo are READY.
- The ignored `config/decomp_campaign.run.local.toml` is limited to one worker,
  two total attempts, 30 minutes and targets only `0x2C28C` / `0x4217C`.
  It keeps OpenAI unknown/false and leaves `continuous`, `pilot_verified`, and
  productive expansion disabled. The versioned defaults in
  `config/decomp_campaign.toml` are unchanged.
- **No campaign was started and no inference was made during preparation.**
  `status` still reports zero model-process attempts, 0 matched functions, and
  0 matched instructions.
  After the operator explicitly confirms, the one-shot pilot command is:

  ```powershell
  py -3.12 scripts/decomp_campaign.py --config config/decomp_campaign.run.local.toml run --confirm --allow-free-model-usage --max-tasks 2
  ```

- TDD RED reproduced the defect: the preflight never queried `/api/model`, so
  the valid public/no-stored-auth case failed. GREEN now covers public zero-cost
  readiness, nonzero/incomplete or
  missing/invalid/contradictory metadata, OpenAI remaining BLOCKED, and denied
  worker permissions. Targeted tests: **14 passed**; orchestrator suite:
  **55 passed**; full suite: **890 passed, 44 skipped**. `compileall` and
  `git diff --check` are clean. EBOOT remains **8/206** and PRXs **16/912**.
