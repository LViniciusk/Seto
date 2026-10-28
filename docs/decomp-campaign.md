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
available. No inference was made during SETO-DECOMP-039 or R3. R4 made exactly
one nonproductive OpenAI diagnostic request; the campaign database has zero
attempts and zero matched progress.

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
| OpenAI model | **READY in the ignored R4 pilot profile** — operator confirmed `chatgpt-token-sharing`; OpenCode reports one saved OAuth credential, the native provider/default endpoint is active with no gateway/header/body override, and one minimal diagnostic request succeeded. The CLI does not expose the OAuth method tied to the saved credential, so the local profile records this explicit operator confirmation. |
| DeepSeek Free | **READY** — exact model metadata proves `apiKey=public`, active/enabled status, and zero input/output/cache cost; operator access was independently confirmed in R3 and preserved in R4 |
| Worker agent | `seto-decomp-worker` is discovered and its effective policy is restricted in both checkout and campaign worktree: shell/external paths denied; edits limited to candidate C and campaign build paths; AIMemory query/read only |
| Campaign | Pilot prepared but **not started**. Versioned defaults remain disabled; the ignored R4 profile selects both READY workers, is capped at four total attempts / 30 minutes, and still requires explicit `run --confirm` plus both usage flags |

OpenCode's [provider guide](https://opencode.ai/v2/docs/providers) distinguishes
ChatGPT-plan sign-in from API-key usage; its [CLI provider guide](https://opencode.ai/v2/docs/cli/providers/)
documents saved OAuth credentials and environment connections. OpenCode 2.1.4's
`auth list --format json` reports only generic `oauth`, not which OAuth method
created that credential. R4 therefore required an explicit operator confirmation
of the advertised `chatgpt-token-sharing` method, alongside one unambiguous saved
OAuth credential, no environment credential, the native OpenAI provider, and the
default `https://api.openai.com/v1` endpoint with no custom headers/body or model
route override. The official provider guide says ChatGPT-plan usage counts against
the plan. An empty catalog `cost` object is not used as evidence of free usage.
The [model catalog](https://opencode.ai/v2/docs/models) listing alone is not
treated as proof that a project can execute a model.

The repository does not copy or edit the existing global OpenCode/AIMemory
configuration. The broad legacy project default is overridden for campaign
sessions by `.opencode/agents/seto-decomp-worker.md`; `doctor` inspects OpenCode's
effective agent rules rather than trusting that file alone. The R3 review
checked the effective rules in both the checkout and actual campaign worktree.
Workers have no shell, subagent, or external-directory permission and can edit only candidate
sources/campaign artifacts. Worktree preflight rechecks AIMemory connectivity.
Workers may query/read AIMemory but may not write or message it. No credentials,
media, or dumps are recorded in AIMemory or the campaign ledger.

## A future, separately confirmed pilot run

SETO-DECOMP-040 made exactly one **nonproductive diagnostic** model request in
R4; the campaign itself was not started. Stored authentication alone does not
make OpenAI READY, and DeepSeek's catalog entry alone does not prove access. The
OpenAI preflight additionally requires the explicit OAuth-method confirmation
described above. The R3 DeepSeek preflight accepts the exact Free model only when
current `/api/model` metadata proves public auth, active/enabled state and zero
cost, and the operator has separately verified access. The configured workers are:

* `openai/gpt-6-luna` via provider `openai` (requires proven subscription-included usage; API-key/billable mode is rejected)
* `opencode/deepseek-v4.1-flash-free` via provider `opencode` (requires exact public model metadata, verified access, and exact Free usage)

The ignored R4 local profile records the operator-confirmed OpenAI method as
`auth_method_confirmed = "chatgpt-token-sharing"`; preflight still rejects API
keys, environment credentials, ambiguous accounts, unknown methods, and custom
routes. On another machine, do not copy that confirmation: the operator must
verify the selected method in `/connect` or `opencode auth login openai`, then
record it only in that machine's ignored profile. Set `access_verified = true`
only after the separate minimal test succeeds. The ordinary `run` command is the
**pilot**: it is restricted to
`0x2C28C` and `0x4217C`, max 4 total attempts with two READY providers (max 2
with only one), and a 30-minute deadline. Pass only the confirmation flag(s) for
the READY worker(s):

```powershell
py -3.12 scripts/decomp_campaign.py --config config/decomp_campaign.run.local.toml run --confirm --allow-openai-usage --allow-free-model-usage --max-tasks 4
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

`resume` clears only the campaign stop flag; it does not change provider status,
quota/auth reasons, resume deadlines, or timestamps. Use `--retry-blocked` only
after diagnosing and fixing the underlying cause. Resuming tasks never releases
quota: a provider must be independently verified and selectively authorized
before it can run again. Rate limits honor `Retry-After`, provider outages back
off, and a run exits instead of polling when no worker can claim a task.

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

## SETO-DECOMP-040-R4 — ChatGPT subscription preflight (2026-10-25)

- The operator explicitly confirmed that the single saved OpenAI account was
  connected with **Sign in with ChatGPT** (`chatgpt-token-sharing`). OpenCode
  2.1.4 exposes only generic `method="oauth"` for the saved credential; it does
  not link that credential to a specific OAuth method ID. No account was
  switched, changed, or disconnected. `auth list --format json` showed one saved
  OpenAI credential and no environment connection. The effective provider uses
  OpenCode's native package and default OpenAI endpoint, without a custom
  gateway, API-key override, custom request headers/body, or model-level route
  override. Credential values were not read or recorded.
- `openai/gpt-6-luna` was present, active, and enabled. Its empty catalog cost
  metadata was **not** treated as billing evidence. The official V2 provider
  documentation identifies ChatGPT-plan sign-in as plan usage; because the CLI
  cannot distinguish the saved OAuth method, the ignored local profile records
  the explicit operator confirmation.
- One minimal, nonproductive Luna request succeeded in a
  `seto-decomp-worker` session located in the OpenAI worktree. The effective
  restricted policy passed; the session retained the exact agent/model and
  OpenCode's `variant="default"`. No tool call or project work was made. Only
  success, model, modality, and session identity were recorded; response content
  and session ID were not recorded.
- Session validation now compares the exact provider/model identity and accepts
  OpenCode's implicit default variant; a non-default variant still causes a
  session replacement. Preflight uses `auth list --format json` without
  persisting account IDs, labels, or credential values. API keys, environment
  credentials, ambiguous accounts, unknown methods, custom routes, unavailable
  models, and insufficient permissions remain BLOCKED. DeepSeek Free readiness
  remains independent and unchanged; an empty OpenAI cost object is ignored.
- The ignored R4 profile selects both READY workers, one per model, with
  `limits.max_workers=2`, four total pilot attempts, a 30-minute limit, and only
  `0x2C28C` / `0x4217C`. `continuous`, `pilot_verified`, and productive expansion
  remain false. The local `libtutoriallist.prx` hash typo was corrected to match
  the versioned baseline; source files were not changed.
- The checkout and both campaign worktrees pass `doctor`: OpenCode 2.1.4,
  OpenAI and DeepSeek READY, AIMemory connected, restricted agent policy, WSL
  Python 3.12.3, Ghidra, MWCC, and wibo READY. Both worktrees are clean at
  `4e7c606` before R4 code changes. The campaign was not started; EBOOT and PRX
  baselines remain **8/206** and **16/912**. TDD RED reproduced the missing
  subscription/route checks and the false session mismatch on `variant="default"`;
  GREEN: orchestrator **72 passed**, full suite **907 passed / 44 skipped**,
  `compileall` and `git diff --check` clean.
