# psh — Physician-Scientist Harness

A governed control plane for physician-scientist work. Not a bigger agent: the layer your
agents, tools and harnesses run *through*.

Positioning, stated precisely, because the earlier "Kubernetes for AI agents" framing
promised hard isolation, distributed scheduling and multi-tenancy that this does not have:

> **A policy-enforced control plane for biomedical scientific agents.** Research prototype.

## v0.5.1 — gate composition

v0.5 asked whether each control was on the path that executes. A second review ran the
result and asked the next question down: **does the control see everything it is deciding
about?** Twelve findings, every one reproduced by running the code before it was fixed and
pinned by a test afterwards (`tests/test_gate_composition.py`, and per-dimension property
tests in `tests/test_authority_property.py`). Full detail in
`docs/V5_1_GATE_COMPOSITION.md`.

| Closed | What was wrong |
| --- | --- |
| **The kernel is the policy root** | `Runner(policy=…)` replaced `kernel.policy` unchecked. A `peer_review` kernel — "no network egress of any kind" — handed a `literature` policy made a successful public model call: `model_calls=1, refusals=0`. A run policy is now contained by the kernel's on every dimension (`clamp_policy=True` narrows instead of refusing). |
| **A gate reads every destination** | `ToolGateway` read `destinations[0]`, so a component declaring `(LOCAL_COMPUTE, PUBLIC_REMOTE)` was judged local and PHI passed — while the isolated executor read the same tuple with `any()` and opened the network for it. |
| **A prompt is a question, not a verdict** | An execution-policy `prompt` returned `allowed=True` immediately, skipping the absolute denylist and the path check behind it: `git push --force` and a write to `/etc/passwd` both came back allowed. |
| **Unverifiable is refused** | The payload walker returned `[]` when it hit its depth limit, so burying a path nine levels deep defeated the check. Truncation is now reported and refused. |
| **One authority predicate** | `DelegationGateway` hand-rolled containment over four dimensions beside a lattice covering sixteen; a child with R4/ACT, unrestricted capabilities and 999× the budget was allowed. The property test missed it because its child widened *every* dimension at once and always failed on tokens first — it is now one dimension at a time, verified non-vacuous by mutation. |
| **A ceiling of zero is not "exceeded"** | `state.usd >= usd_hard` fires at zero spend, so `peer_review` (`usd_hard=0.0`, local models only) refused every run it was given. |
| **Persistence obeys the run** | `PersistenceGateway` never looked at the envelope, so a `peer_review` run wrote its task node — manuscript text as the title — into `index.db`. Such runs are now **ephemeral**: gated, verified, released and event-logged, but nothing durable is written. |
| **Chinese text is not invisible** | Four ASCII-only tokenisers: distinct Chinese memories deduplicated to one, a Chinese claim scored 0% overlap against its own source, Chinese queries ranked by cost alone, and 姓名+住院号+身份证号+手机号 classified INTERNAL — releasable to a public provider. One CJK-aware segmenter (`psh/text.py`) plus Chinese identifier rules. |
| **Isolation holds at its edges** | `manifest.id="../../escaped"` put a subprocess outside the sandbox root; a timeout killed the process but not the process group it created (a grandchild outlived it and wrote a file); `allowed_hosts` was consumed twice; non-JSON stdout was silently accepted. |
| **Manifest contracts are enforced** | `requires_network` validation was a chained comparison that can never be true; `min_autonomy` was read nowhere (and defaulted to `ACT`, which nothing noticed because nothing enforced it). |
| **The loop detector detects loops** | Keyed on an always-empty `task_id`, counted globally, never cleared: three independent users asking the same question got `ok, ok, StuckLoop`. |
| **Lifecycle and settings** | `Runner` reuses `kernel.graph` instead of opening a second unclosed SQLite connection; `Quarantine` recomputes paths so its "survives process death" claim is true; `Runner.STAGES` matches the stages a run emits; `context_token_budget` is applied and the three settings nothing reads are listed as `PENDING_FIELDS` with a test that pins them. |

`clinical_research` now sets `require_isolated_tools=True` — the switch existed in v0.5 and
`WorkProfile` had no field to reach it, so the profile's own notes described a posture it
could not adopt. In-process tools are refused under that profile.

## v0.5 — enforcement closure

| Closed | What was wrong |
| --- | --- |
| **Policy is a ceiling** | `PolicySnapshot.envelope()` read `kw.pop("risk", self.risk_ceiling)`, so the ceiling applied only to callers who declined to state a value. `R2`/`SUGGEST` policies minted `R4`/`ACT` envelopes on request. Every dimension is now checked against the ceiling by `AuthorityLattice`; widening raises, `clamp=True` narrows instead. |
| **One minting path** | `TrustedKernel.envelope()` never consulted `self.policy` at all — it minted from hard-coded defaults (`PHI`, `ACT_WITH_APPROVAL`, four destinations). It now delegates to the policy, so a `peer_review` kernel cannot hand out a network envelope. |
| **Isolation on the real path** | `IsolatedRunner` shipped in v0.4 and `ExecutionBroker.call_tool` ran every component with `component.invoke(...)` *inside the kernel process* — a tool could read `os.environ` and open its own socket. Components declaring `backend="subprocess"` now run through the runner; the two paths are counted separately, the audit event records which ran, and `require_isolated_tools` refuses the in-process one outright. |
| **Approvals key on the action** | A session approval was keyed on the string `"run shell"`, so approving `git push origin main` for the session also pre-approved `curl … | sh`. The key is now a digest over request kind, component, normalised argv (or payload digest), targets and risk. |
| **Grants cannot unset the boundary** | `build_child_environment` wrote the proxy variables and then applied caller grants over them, so `HTTP_PROXY=http://evil:9999` / `NO_PROXY=*` disabled the egress boundary from inside. Kernel-reserved names are applied last and refused as grants. |
| **No DNS rebinding, ports are capabilities** | The proxy validated a hostname and then handed the *name* to `create_connection`, which resolved it again. It now connects to the addresses the decision vetted, refuses names that do not resolve, treats `host` as ports 80/443 (`host:8443`, `host:*` to say otherwise), and derives the forwarded `Host:` from the vetted URI instead of the client's header. |
| **Filesystem containment after resolution** | Path checks were `fnmatch` over the payload's own string, so `/allowed/../secret` and a symlink out of `/allowed` both passed. Paths are now resolved (`..`, symlinks, `~`) and must land inside an allowed root; nested payloads are walked. |
| **External hooks are contained** | A `PreToolUse` command hook received the fully unwrapped payload and ran under a bare `subprocess.run` — PHI reaching a third-party process with unsupervised network access, through a door the broker does not watch. External hooks now run through the same isolated runner (no network by default) and receive a redacted view; in-process hooks are trusted and unchanged. |
| **The output gate is not English-only** | Clinical assertions in Chinese and reported statistics (`AUC`, odds ratio, `p < 0.001`, 敏感性/死亡率) were invisible to the gate, and CJK text split into a single "sentence". Both are recognised now. |

Also: `TrustedKernel.close()` releases the WorkGraph connection as well as the event store;
`hypothesis` is a declared test dependency (the authority property tests silently skipped
without it); `live` tests are deselected by default in `pyproject.toml` rather than by
remembering a flag; AppleDouble `._*` sidecars are gone from the tree and ignored (they
contain NUL bytes and break `python -m compileall`).

Run tests:

```bash
python -m pytest tests/ -q          # 314 pass; `-m live` opts into network tests
python -m compileall -q src         # clean
```

`hypothesis` is required, not optional: without it the authority-monotonicity property
tests — the only exhaustive check of the lattice — used to skip silently, and a run that
reports "223 passed, 1 skipped" is hiding the coverage that matters. They now fail instead
(`PSH_ALLOW_MISSING_HYPOTHESIS=1` opts out deliberately).

## What is enforced, and what is not

Enforced, with a test that drives the executing path:

* no value reaches a gateway unclassified, and a caller-supplied label is re-validated;
* no envelope is wider than the policy that minted it, and no run policy is wider than the
  kernel's, on any of the lattice's dimensions;
* every model call, tool call and delegation passes the broker, which records an event;
* a tool call is judged against every destination its component declares, and a payload the
  gate cannot finish walking is refused rather than assumed clean;
* a run under a profile without `PERSISTENT` writes nothing durable;
* output is quarantined and `released_output` stays `None` unless the release gate passed;
* a `backend="subprocess"` component cannot read the kernel's environment, cannot escape the
  sandbox root through its own id, and cannot outlive its timeout through a child process;
* Chinese and English are handled by the same classification, dedup, retrieval and
  claim-support machinery.

**Not** enforced, stated plainly:

* a `backend="python"` component runs in the kernel process and is confined by nothing.
  This is the honest boundary: `require_isolated_tools=True` is how a policy refuses it.
* the egress proxy governs clients that honour proxy variables. A raw socket bypasses it.
  `SandboxBackend` is the seam for the OS layer (Seatbelt, bubblewrap+seccomp); only
  `NoSandbox` ships, and it says so in `describe()`.
* the audit chain is tamper-evident, not tamper-proof; classification is a safety net, not
  certified de-identification; claim support is lexical; the planner is a placeholder.

## Install

```bash
pip install -e .            # standalone; classification degrades and says so
pip install -e .[test]      # pytest + hypothesis
```

Run tests with `PYTHONPATH=src` (or `PYTHONPATH=../sable_pkg/src:src` for the composed
configuration) — editable installs may not survive a session restart.

## Use

```python
from psh import get_profile
from psh.kernel import TrustedKernel
from psh.runtime import Runner

policy = get_profile("clinical_research").freeze()   # local only, PHI ceiling
kernel = TrustedKernel(policy=policy)
runner = Runner(kernel, model=local_model, model_invoke=my_provider, policy=policy)

result = runner.run("Summarise the HFpEF evidence", sources={"34449189": abstract})
if result.released_output is None:
    print("refused:", result.error, "| quarantined as", result.quarantine_ref)
```

The policy is a ceiling: `runner.run(..., risk=RiskTier.R4_KERNEL)` under this profile is
refused at the `policy_snapshot` stage, not honoured. Ask for less than the profile grants
and you get it; ask for more and you get a `PolicyDenied` naming the dimension.

`clinical_research` is deliberately unusable without a local model. That is the profile
working as intended.

## What this is not

There is no agent loop. `_plan()` splits sentences and `resolve` injects capability
manifests into a prompt; there is no typed plan, no tool → observation → replan cycle, no
executor. The strong parts are policy, evidence, provenance, the WorkGraph and the gateways
— which is why the line at the top says *control plane*, and why "framework" would be an
overclaim. Building that middle layer is the next release's work, not this one's.

## Earlier releases

* **v0.4** — six enforcement patterns adopted from Codex (read from source) and Claude Code
  (official docs), attributed per pattern in `PATTERN_ATTRIBUTION.md`: declarative
  self-testing execution policy, approval-to-rule amendments, absolute-deny evaluation
  order, the shared hook JSON protocol, default-deny child environments, a kernel-owned
  egress proxy refusing private ranges even when allowlisted.
* **v0.2** — sixteen externally-found defects closed as invariants: mandatory ingress, deep
  labelling, one authority predicate, release before exposure, classified persistence,
  evidence provenance, real token/cost accounting.

## Scope

Research prototype. Not clinical-safe, not production-ready.
`docs/V5_1_GATE_COMPOSITION.md` and `docs/V5_ENFORCEMENT_CLOSURE.md` list what each release
closed and what it deliberately left open — including that no OS sandbox ships, so a
`backend="python"` component is confined by nothing. MIT licensed.
