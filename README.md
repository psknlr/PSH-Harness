# psh — Physician-Scientist Harness

A governed control plane for physician-scientist work. Not a bigger agent: the layer your
agents, tools and harnesses run *through*.

Positioning, stated precisely, because the earlier "Kubernetes for AI agents" framing
promised hard isolation, distributed scheduling and multi-tenancy that this does not have:

> **A policy-enforced control plane for biomedical scientific agents.** Research prototype.

## v0.5 — enforcement closure

No new subsystems. This release closes the gap an external review measured between what the
package *implements* and what its *executing path* uses. The defects shared one shape — a
control that exists, a main path that does not call it, and a README describing the
control — and each is now closed with a test that drives the main path:

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
python -m pytest tests/ -q          # 230 pass; `-m live` opts into network tests
python -m compileall -q src         # clean
```

## What is enforced, and what is not

Enforced, with a test that drives the executing path:

* no value reaches a gateway unclassified, and a caller-supplied label is re-validated;
* no envelope is wider than the policy that minted it, on any of the lattice's dimensions;
* every model call, tool call and delegation passes the broker, which records an event;
* output is quarantined and `released_output` stays `None` unless the release gate passed;
* a `backend="subprocess"` component cannot read the kernel's environment.

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

Research prototype. Not clinical-safe, not production-ready. See
`docs/V5_ENFORCEMENT_CLOSURE.md` for the review items this release closes, and the ones it
deliberately leaves open. MIT licensed.
