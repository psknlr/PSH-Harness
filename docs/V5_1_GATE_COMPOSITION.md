# v0.5.1 — gate composition

v0.5 answered the question *"is the control on the path that executes?"*. A second external
review ran the result — reproduction scripts, not readings — and asked the next question
down: *"does the control see everything it is deciding about?"* It found a family of defects
with a shared shape, and the shape is worth naming because it is not the v0.5 shape:

> The gate is on the path, it runs, it returns a verdict — and it reached that verdict from
> a partial view: the first element of a tuple, a payload it stopped walking, a policy it
> was handed instead of the one it is meant to enforce, a comparison written beside the
> comparison that already exists.

Three findings were rated above several of the first review's P1s, and all three were
confirmed here by running the code: a zero-cost budget that made `peer_review` refuse every
run, an execution-policy `prompt` verdict that skipped the absolute denylist behind it, and
`require_claim_support` never reaching the output gate.

## Closed

### 1. The kernel is the policy root again — `runtime/runner.py`

`Runner(policy=…)` and `run(policy=…)` replaced `kernel.policy` with no containment check.
A `peer_review` kernel — "no network egress of any kind" — handed a `literature`-shaped
policy ran a successful `PUBLIC_REMOTE` model call: `model_calls=1, refusals=0`. Nothing in
the gates misbehaved; they enforced an envelope minted under a policy the kernel never
agreed to.

A run policy is now contained by the kernel's, on every dimension, at construction and at
each `run()`. `Runner(..., clamp_policy=True)` narrows instead of refusing.

This also closes the split-brain the review described, where `result.policy_snapshot` and
the policy the gates actually applied could differ: a contained run policy is never wider
than the kernel's, and the two places where a run policy can be *stricter* now carry that
strictness to the gate — `require_claim_support` and `require_citation` are passed per call
to `OutputGate.check`, and `require_isolated_tools` rides on the `RunEnvelope`.

### 2. A gate reads every destination — `kernel/egress.py`

`ToolGateway.check` read `manifest.destinations[0]`. A component declaring
`(LOCAL_COMPUTE, PUBLIC_REMOTE)` was judged as local, so PHI passed — while
`IsolatedExecutor.allowed_hosts` read the same tuple with `any()` and opened the network for
it. One gate reading the first element while the next reads all of them is how a label check
and a capability grant come to disagree. Every destination is now checked, against both the
payload's label and the run's permitted set, and `EgressDecision.destinations` carries them
all into the audit record and the approval request.

### 3. A prompt is a question, not a verdict — `kernel/egress.py`

An execution-policy `prompt` decision returned immediately with `allowed=True`, skipping the
`DENIED_COMMANDS` denylist and the allowed-path check behind it. `git push --force` —
documented as "refused regardless of autonomy" — and a write to `/etc/passwd` both came back
allowed. The prompt now records that approval is required and the remaining checks still
run.

### 4. An unverifiable payload is refused — `kernel/egress.py`

The path walker returned `[]` when it hit its depth limit, and the caller could not
distinguish "this payload names no paths" from "I stopped looking". Nesting a target nine
levels deep defeated the check. `_collect_paths` now reports truncation (depth *and* node
budget) and the gate refuses on it — the rule `labels.deep_label_of` already applied to its
own walk.

### 5. Delegation uses the one authority predicate — `kernel/egress.py`

`DelegationGateway.check` hand-rolled containment over four dimensions beside an
`AuthorityLattice` that covers sixteen. A child with `R4`/`ACT`, unrestricted capabilities,
none of the parent's denials and 999× the cost, time and call ceilings was allowed, while
`AuthorityLattice.violations` named all nine on the same pair. The gateway now calls the
lattice; only the projection-label check, which is not an authority dimension, remains local.

**Why the property test did not catch it.** `test_delegation_contract_cannot_exceed_its_parent_run`
built a child that was maximal on *every* dimension at once, with `tokens_hard = 10**9`
against a parent strategy topping out at 100 000 — so every generated case failed on
`budget.tokens_hard` before any other dimension was consulted. A property test whose first
condition always dominates tests that one condition. It is now parameterised: one widened
dimension at a time, each required to be named. Verified non-vacuous by mutation — disabling
the lattice's autonomy check turns exactly the two `[autonomy]` parameterisations red.

### 6. A ceiling of zero is not "exceeded" — `kernel/budget.py`

`state.usd >= budget.usd_hard` is true before a run spends anything. `peer_review` sets
`usd_hard=0.0` deliberately (local models only) and therefore refused every run with
`BudgetExhausted: $0.00 >= $0.00`: the profile was unusable. Hard ceilings are now breached
by *exceeding* them, and soft warnings require non-zero usage.

### 7. A profile that forbids persistence writes nothing — `kernel/persistence.py`

`PersistenceGateway` checked the label against the store's ceiling and never looked at the
envelope, so `PERSISTENT` being absent from a profile meant nothing at the sink. A
`peer_review` run wrote its task node — with the manuscript text as the title — into
`index.db`. The gateway now refuses a durable write the run may not make, and `Runner`
detects the same condition and runs **ephemerally**: classify, gate, verify, release and the
hash-chained event record all still happen; nothing durable is written.

### 8. Chinese text is no longer invisible — new `psh/text.py`

Four modules each had their own ASCII-only tokeniser:

| Module | Effect |
| --- | --- |
| `context/compiler._fingerprint` | every CJK-only item fingerprinted to `""`; three distinct Chinese memories deduplicated to one (`candidates=3 → included=1`) |
| `evidence/support._tokens` | a Chinese claim quoted verbatim from its Chinese source scored 0% overlap → UNKNOWN |
| `capabilities/registry._terms` | a Chinese query produced an empty term set; ranking collapsed to cost/latency |
| `kernel/classify` fallback | 姓名 + 住院号 + 身份证号 + 手机号 classified INTERNAL — below the PUBLIC_REMOTE ceiling, therefore releasable to a public provider |

The first three now share one CJK-aware segmenter (character bigrams, the standard
dictionary-free approach, plus Latin words and numbers). The fourth gains Chinese identifier
rules — mainland ID, mobile, 住院号/病案号/门诊号, surname-cued names, 出生日期 — applied
*in addition to* whichever detector is active, because sable's rule set is English.

Note what these two defects did together: the output gate learned to recognise Chinese
clinical assertions in v0.5, and the verifier could not support any of them. Every Chinese
clinical sentence was permanently unreleasable — a gate demanding evidence the verifier was
structurally unable to find.

### 9. Isolation holds at its edges — `kernel/isolation.py`

* **Workdir traversal.** `workdir_root / run_id / manifest.id` with `id="../../escaped"` put
  the subprocess outside the sandbox root; an absolute id would have discarded the root
  entirely. `ComponentManifest` now refuses an id that is not a safe path component, and the
  executor independently verifies the resolved directory is inside the root.
* **Timeout killed a process, not a process group.** `start_new_session=True` created the
  group and nothing used it: a grandchild outlived "timeout and was killed" and went on to
  write a file. `Popen` + `killpg` now takes the tree, on timeout and on normal exit.
* **`allowed_hosts` was consumed twice** — a generator passed by a caller yielded `False`
  for `allow_network` after the first `list()`.
* **Protocol violations are violations.** Non-JSON stdout was silently returned as
  `{"stdout": …}`, making a broken contract indistinguishable from a text result.

### 10. Manifest contract fields are enforced — `contracts.py`

* `Destination.LOCAL_COMPUTE == self.destinations == ()` is a chained comparison that can
  never be true, so the `requires_network` validation never ran; a network component could
  declare no destination and then be gated as `LOCAL_COMPUTE`.
* `min_autonomy` was read nowhere. It is now part of `compatible_with`, and its default
  changed from `ACT` to `OBSERVE` — the old default meant "every component demands full
  autonomy", which nothing noticed precisely because nothing enforced it.

### 11. The loop detector detects loops — `runtime/runner.py`

The key was `f"{envelope.task_id}:{hash(request)}"` while `run()` always minted
`task_id=""`, so the key was the request alone, the count was global to the Runner and never
cleared, and three independent users asking the same question got `ok, ok, StuckLoop`.
Detection is now scoped to a unit of work (`task_id=` on `run()`, or a parent run for a
delegated child); a one-shot top-level run is not counted.

### 12. Lifecycle, settings and documentation

* `Runner` reuses `kernel.graph` instead of opening a second, never-closed SQLite connection
  to the same index.
* `Runner.STAGES` is bound to the module `STAGES` rather than restating a thirteen-name copy
  that no run has emitted since v0.1.
* `Quarantine` recomputes a reference's path instead of relying on an in-memory index, so
  the "survives process death" claim in its docstring is true.
* `PolicySnapshot.with_()` covers every dimension, and a new test fails if a field is added
  to the snapshot without a containment decision.
* `config.context_token_budget` is applied; `compaction_threshold`,
  `offload_threshold_bytes` and `max_retries` are listed as `PENDING_FIELDS` with a test
  that fails if one silently starts or stops being used.
* `psh.__version__` matches `pyproject.toml` (a test now asserts it), and the package
  docstring's quick start no longer calls two methods that have raised since v0.2.
* Missing `hypothesis` is a **failure**, not a skip: it is a declared test dependency, and
  the checks it gates are the only exhaustive coverage of the lattice. Opt out deliberately
  with `PSH_ALLOW_MISSING_HYPOTHESIS=1`.

## Still open, deliberately

The first review's list stands, minus what is closed above. Two items are worth restating
because this release is where they became the *largest* remaining gaps:

1. **No OS sandbox.** Everything in §9 hardens a boundary that a raw socket still walks
   around. `SandboxBackend` is the seam; Seatbelt / bubblewrap+seccomp is the next real
   security increment and nothing else on this list competes with it.
2. **There is no agent loop.** The review's structural point is correct and worth quoting:
   the strongest parts of psh are policy, evidence, provenance, WorkGraph and the gateways;
   the weakest is the middle, where a planner would produce a typed plan and an executor
   would run tool → observation → replan. `_plan()` is a sentence splitter and `resolve`
   only injects capability manifests into a prompt. Until that exists, the honest
   description is a **control plane and runtime substrate**, not an agent framework — which
   is why the README says exactly that.

Also unchanged: claim support is lexical without a verification model; scientific artifacts
(figures, tables, statistics) are not typed; ontology verdicts are not version-pinned;
`close != revoke`; the audit chain is tamper-evident, not tamper-proof.

## Reproductions, now regression tests

Every finding above is pinned by a test in `tests/test_gate_composition.py`, and the
lattice's per-dimension coverage by `tests/test_authority_property.py`. The four that were
most load-bearing:

```python
# 1. a wider run policy
Runner(kernel_under_peer_review, policy=literature_policy)      # PolicyDenied

# 2. the second destination
tool_gateway.check(phi, manifest_with(LOCAL_COMPUTE, PUBLIC_REMOTE), env).allowed   # False

# 3. the prompted command
tool_gateway.check({"command": "git push --force origin main"}, shell, env).allowed # False

# 4. the zero-cost profile
Runner(kernel, policy=get_profile("peer_review").freeze()).run("...").status        # "ok"
```
