"""Process-isolated tool execution behind a kernel-owned egress proxy.

This module raises psh's boundary from *in-process cooperation* to *process level*. It is the
direct response to my own audit's finding A1: any code inside the kernel process can call a
provider and the broker sees nothing. Both surveyed systems answer that finding the same way
— the operating system enforces the boundary — and this is the portable part of their answer.

Borrowed from Codex, with file paths:

* **Default-deny environment** — `codex-rs/core/src/exec_env.rs` ("env_clear() to ensure no
  unintended variables are leaked to the spawned process"), `hooks/src/engine/command_runner.rs`.
  A tool subprocess starts from an EMPTY environment and receives only what the run envelope
  grants. A scrub list misses the variable you did not think of; ``env_clear()`` does not.
* **Egress proxy as the network boundary** — `codex-rs/network-proxy/README.md`: a local proxy
  enforcing an allow/deny host policy, with private-range destinations refused unless
  explicitly allowlisted. `exec-server-protocol/src/network_policy.rs` has the same three-way
  Allow / Deny / Ask decision as execpolicy. Here: a kernel-owned HTTP CONNECT + plain-HTTP
  proxy on loopback; the subprocess's ``HTTP_PROXY``/``HTTPS_PROXY`` point at it; every
  decision is an event.
* **Process hardening** — `codex-rs/process-hardening/src/lib.rs` strips ``LD_PRELOAD`` /
  ``DYLD_*`` and disables core dumps pre-main. The env_clear above already excludes the
  loader variables; core-dump limits are applied via ``resource`` in the child's preexec.

What is enforced here, and what is not
--------------------------------------
Enforced and tested from inside this session:

* A tool subprocess cannot read the kernel's environment (credentials, proxy settings for
  anything else, ``PYTHONPATH``).
* A subprocess that honours proxy variables — every mainstream HTTP client does by default —
  is refused for a host outside the envelope's allowlist, and the refusal is an event.
* Private and loopback destinations are refused by default even through the proxy.
* The subprocess runs under a wall-clock limit, a memory limit and with core dumps disabled.

NOT enforced here, and stated plainly: a subprocess that opens a raw socket, or sets
``no_proxy``, bypasses the proxy. Codex closes that with Seatbelt (macOS) / bubblewrap +
seccomp (Linux) denying network to the process; Claude Code with the same two. Neither can be
installed or verified from inside this session, so ``SandboxBackend`` is an adapter interface
with a ``NoSandbox`` implementation that says so in ``describe()``. The proxy is a *policy*
layer; the OS sandbox is the *enforcement* layer, and only the first ships here.
"""

from __future__ import annotations

import ipaddress
import json
import re
import os
import select
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from ..contracts import PolicyDenied

__all__ = ["EgressProxy", "ProxyUnavailable", "HostDecision", "IsolatedRunner", "IsolatedResult",
           "SandboxBackend", "NoSandbox", "build_child_environment", "IsolatedExecutor",
           "IsolationUnavailable", "RESERVED_ENV"]


# ------------------------------------------------------------------ host policy

@dataclass(frozen=True, slots=True)
class HostDecision:
    host: str
    port: int
    allowed: bool
    reason: str
    #: The addresses this decision vetted. The connection is made to one of *these*, never
    #: by re-resolving the name — see ``_HostPolicy.decide``.
    addresses: tuple[str, ...] = ()
    at: float = field(default_factory=time.time)


#: Ports a bare hostname pattern permits. A pattern may name its own (``host:8443``) or
#: open all of them (``host:*``). "The run may reach api.example.org" and "the run may reach
#: anything api.example.org happens to be listening on" are different capabilities, and the
#: second is not what an allowlist entry is usually meant to grant.
DEFAULT_PORTS: frozenset[int] = frozenset({80, 443})

#: Resolve a hostname to the addresses a connection would use. Injectable so a unit test
#: never touches DNS: in v0.4 ``_HostPolicy.decide`` called ``getaddrinfo`` unconditionally,
#: so tests that looked purely local blocked on name resolution and could not run offline.
Resolver = Callable[[str], "Sequence[str]"]


def _system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0].split("%")[0] for info in infos))


def _is_private_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified)


def _split_pattern(pattern: str) -> tuple[str, str | None]:
    """Split ``host[:port]``, leaving bracketed IPv6 literals intact."""
    if pattern.startswith("["):
        host, _, rest = pattern.partition("]")
        return host[1:], (rest[1:] if rest.startswith(":") else None)
    host, sep, port = pattern.rpartition(":")
    if not sep or not (port.isdigit() or port == "*"):
        return pattern, None
    return host, port


class _HostPolicy:
    """Decides host:port reachability, and resolves the name exactly once while doing it.

    Two properties the v0.4 policy did not have:

    * **No DNS rebinding.** It validated the name, then handed the *name* to
      ``socket.create_connection``, which resolved it again. A resolver that answers with a
      public address the first time and ``169.254.169.254`` the second turns an allowlist
      into an SSRF primitive. The decision now carries the vetted addresses and the handler
      connects to one of them.
    * **Ports are part of the capability.** ``api.example.org`` grants 80 and 443, not every
      port the host is listening on; ``api.example.org:8443`` grants that one.

    A name that does not resolve is refused rather than allowed to fail later: "we could not
    check it" is not "it is fine".
    """

    def __init__(self, allowed_hosts: Iterable[str], *, allow_private: bool = False,
                 audit: Callable[..., Any] | None = None, run_id: str = "",
                 resolver: Resolver | None = None) -> None:
        import fnmatch

        self._patterns = tuple(_split_pattern(h.strip().lower()) for h in allowed_hosts if h.strip())
        self._fn = fnmatch.fnmatch
        self.allow_private = allow_private
        self._audit = audit
        self.run_id = run_id
        self._resolve = resolver or _system_resolver
        self.decisions: list[HostDecision] = []
        self._lock = threading.Lock()

    def _matches(self, host: str, port: int) -> bool:
        for pattern_host, pattern_port in self._patterns:
            if not self._fn(host, pattern_host):
                continue
            if pattern_port is None:
                if port in DEFAULT_PORTS:
                    return True
            elif pattern_port == "*" or pattern_port == str(port):
                return True
        return False

    def _port_named_by_a_matching_pattern(self, host: str) -> bool:
        return any(self._fn(host, ph) for ph, _ in self._patterns)

    def decide(self, host: str, port: int) -> HostDecision:
        h = host.lower().rstrip(".").strip("[]")
        addresses: tuple[str, ...] = ()
        if not self._patterns:
            d = HostDecision(h, port, False, "no network destinations are allowed for this run")
        elif not self._matches(h, port):
            reason = (f"{h}:{port} is not in the run's allowed hosts"
                      if not self._port_named_by_a_matching_pattern(h)
                      else f"{h} is allowlisted but not on port {port}")
            d = HostDecision(h, port, False, reason)
        else:
            try:
                addresses = tuple(self._resolve(h)) if not _is_ip_literal(h) else (h,)
            except OSError as exc:
                d = HostDecision(h, port, False, f"{h} does not resolve ({exc}); refused")
                addresses = ()
            else:
                if not addresses:
                    d = HostDecision(h, port, False, f"{h} resolves to no address; refused")
                elif not self.allow_private and any(_is_private_address(a) for a in addresses):
                    d = HostDecision(
                        h, port, False,
                        f"{h} resolves to a private/loopback address; refused even though "
                        "allowlisted (SSRF guard)", addresses=addresses)
                else:
                    d = HostDecision(h, port, True, "allowlisted", addresses=addresses)
        with self._lock:
            self.decisions.append(d)
        if self._audit is not None:
            self._audit("egress_proxy_decision", host=h, port=port, allowed=d.allowed,
                        reason=d.reason[:120], run_id=self.run_id)
        return d


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_private(host: str, resolver: Resolver | None = None) -> bool:
    """True for loopback, link-local, private and reserved addresses, resolving names.

    Retained for callers that only want the predicate. The proxy itself uses
    ``_HostPolicy.decide``, which resolves once and keeps the answer.
    """
    if _is_ip_literal(host):
        return _is_private_address(host)
    try:
        addresses = (resolver or _system_resolver)(host)
    except OSError:
        return False  # unresolvable: not private, and the connect will fail on its own
    return any(_is_private_address(a) for a in addresses)


# ------------------------------------------------------------------- the proxy

#: Headers that belong to one hop and must never be forwarded upstream. ``Proxy-*`` carry
#: whatever the child used to talk to the kernel's proxy; the rest are connection state.
_HOP_BY_HOP = frozenset({
    "proxy-connection", "proxy-authorization", "proxy-authenticate", "connection",
    "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"})


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP CONNECT tunnelling plus plain absolute-URI HTTP forwarding."""

    protocol_version = "HTTP/1.1"
    policy: _HostPolicy  # set on the server class

    def log_message(self, *_: Any) -> None:  # quiet; decisions are events, not stderr
        pass

    def _refuse(self, decision: HostDecision) -> None:
        body = json.dumps({"refused": True, "host": decision.host, "reason": decision.reason}
                          ).encode()
        self.send_response(403, "Forbidden by egress policy")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_CONNECT(self) -> None:  # noqa: N802
        host, _, port = self.path.rpartition(":")
        try:
            port_i = int(port or 443)
        except ValueError:
            self.send_error(400, "CONNECT requires host:port")
            return
        decision = self.server.policy.decide(host, port_i)  # type: ignore[attr-defined]
        if not decision.allowed:
            self._refuse(decision)
            return
        try:
            upstream = self._connect(decision, port_i)
        except OSError as exc:
            self.send_error(502, f"upstream connect failed: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._pipe(self.connection, upstream)
        self.close_connection = True

    def _forward(self) -> None:
        parts = urlsplit(self.path)
        if not parts.hostname:
            self.send_error(400, "proxy requires an absolute URI")
            return
        port = parts.port or 80
        decision = self.server.policy.decide(parts.hostname, port)  # type: ignore[attr-defined]
        if not decision.allowed:
            self._refuse(decision)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            upstream = self._connect(decision, port)
        except OSError as exc:
            self.send_error(502, f"upstream connect failed: {exc}")
            return
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        req = [f"{self.command} {path} HTTP/1.1"]
        # The Host header is derived from the authority the policy actually vetted, never
        # copied from the client. A child that connects to an allowlisted address while
        # naming a different virtual host in Host: reaches a site the policy never approved
        # — the ordinary shape of a shared-hosting bypass.
        authority = parts.hostname + ("" if port in (80, 443) else f":{port}")
        req.append(f"Host: {authority}")
        for k, v in self.headers.items():
            if k.lower() in _HOP_BY_HOP or k.lower() == "host":
                continue
            req.append(f"{k}: {v}")
        req.append("Connection: close")
        upstream.sendall(("\r\n".join(req) + "\r\n\r\n").encode() + body)
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            self.wfile.write(chunk)
        upstream.close()
        # One exchange per connection. We told the upstream "Connection: close"; the client
        # side closes too, so the handler never blocks waiting for a keep-alive follow-up.
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _forward  # type: ignore[assignment]

    @staticmethod
    def _connect(decision: HostDecision, port: int) -> socket.socket:
        """Connect to an address this decision vetted, never by re-resolving the name."""
        last: OSError | None = None
        for address in decision.addresses or (decision.host,):
            try:
                return socket.create_connection((address, port), timeout=15)
            except OSError as exc:      # try the next vetted address, as a client would
                last = exc
        raise last or OSError(f"no vetted address for {decision.host}")

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    break
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            return
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError:
                    pass


class _ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    policy: _HostPolicy


class ProxyUnavailable(RuntimeError):
    """The host refused to let the kernel bind a loopback listener.

    Some sandboxes (including the one this package was developed in) forbid listening
    sockets altogether. The runner treats this as *no network for the child*, never as
    "run without the proxy" — see IsolatedRunner.run.
    """


class EgressProxy:
    """A kernel-owned HTTP proxy on loopback that enforces the run's host allowlist."""

    def __init__(self, allowed_hosts: Iterable[str], *, allow_private: bool = False,
                 audit: Callable[..., Any] | None = None, run_id: str = "",
                 resolver: Resolver | None = None) -> None:
        self.policy = _HostPolicy(allowed_hosts, allow_private=allow_private, audit=audit,
                                  run_id=run_id, resolver=resolver)
        try:
            self._server = _ProxyServer(("127.0.0.1", 0), _ProxyHandler)
        except PermissionError as exc:
            raise ProxyUnavailable(
                f"cannot bind a loopback listener for the egress proxy: {exc}") from exc
        self._server.policy = self.policy
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "EgressProxy":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True,
                                        name="psh-egress-proxy")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "EgressProxy":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def decisions(self) -> list[HostDecision]:
        return list(self.policy.decisions)

    def stats(self) -> dict[str, Any]:
        ds = self.decisions
        return {"decisions": len(ds), "allowed": sum(d.allowed for d in ds),
                "refused": sum(not d.allowed for d in ds)}


class _DeadProxy:
    """Stands in for the proxy when no network is wanted and no listener can be bound.

    Proxy variables point at a closed loopback port, so a proxy-honouring client fails to
    connect to anything. Same limit as the real proxy: a raw socket is not confined.
    """

    address = "http://127.0.0.1:9"
    decisions: list[HostDecision] = []

    def __enter__(self) -> "_DeadProxy":
        return self

    def __exit__(self, *exc: object) -> None:
        pass


# ------------------------------------------------------------ child environment

#: Variables a child may inherit from the kernel when the envelope grants "inherit_locale".
_SAFE_INHERIT = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HOME")

#: Names the kernel owns in a child environment. A grant may not set them, and they are
#: written after every other source so nothing can displace them. Three families, each for
#: its own reason: the proxy variables ARE the egress boundary for a proxy-honouring client;
#: the loader variables decide what code the child actually executes; ``PATH`` /
#: ``PYTHONPATH`` decide which binary or module a name resolves to.
RESERVED_ENV: frozenset[str] = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
    "PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONDONTWRITEBYTECODE",
    "PYTHONNOUSERSITE", "IFS", "BASH_ENV", "ENV", "SHELLOPTS", "GLIBC_TUNABLES",
    "NODE_OPTIONS", "PERL5OPT", "RUBYOPT"})


def _is_reserved(name: str) -> bool:
    upper = name.upper()
    return (name in RESERVED_ENV or upper in RESERVED_ENV
            or upper.startswith(("LD_", "DYLD_")))


def build_child_environment(*, proxy_address: str | None, grants: Mapping[str, str] | None = None,
                            inherit: Sequence[str] = _SAFE_INHERIT,
                            workdir: Path | None = None,
                            strict_grants: bool = True) -> dict[str, str]:
    """Build a subprocess environment from nothing (Codex ``env_clear`` pattern).

    Nothing is inherited by default except the short safe list. Loader variables
    (``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``DYLD_*``) can never be inherited because they
    are not in the safe list — there is no scrub step to get wrong.

    **Order matters, and v0.4 had it backwards.** It wrote the proxy variables and then
    applied the caller's grants over the top, so a grant of

        HTTP_PROXY=http://evil:9999   NO_PROXY=*

    replaced the kernel's own egress configuration in the child — the grant mechanism
    disabling the boundary it was supposed to run behind. The kernel's reserved variables
    are therefore applied **last**, and a grant naming one is refused outright rather than
    silently dropped: a caller who asked to set ``LD_PRELOAD`` should hear "no", not
    discover later that it did nothing.
    """
    env: dict[str, str] = {}
    for key in inherit:
        if key in os.environ and not _is_reserved(key):
            env[key] = os.environ[key]

    # 1. caller grants, which may set anything that is not reserved.
    for key, value in (grants or {}).items():
        name = str(key)
        if _is_reserved(name):
            if strict_grants:
                raise PolicyDenied(
                    f"{name} is reserved by the kernel and cannot be granted to a child "
                    "process: it selects the binary that runs, the libraries it loads, or "
                    "the egress path it takes")
            continue
        env[name] = str(value)

    # 2. kernel-reserved variables, applied last so nothing above can displace them.
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin") if "PATH" in inherit else "/usr/bin:/bin"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    if workdir is not None:
        env["HOME"] = str(workdir)
        env["TMPDIR"] = str(workdir)
    if proxy_address:
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY",
                    "all_proxy"):
            env[key] = proxy_address
        env["NO_PROXY"] = env["no_proxy"] = ""
    return env


# ------------------------------------------------------------- sandbox backend

class SandboxBackend(Protocol):
    """OS-level enforcement: the layer this session cannot install or verify."""

    def wrap(self, argv: Sequence[str], *, workdir: Path, allow_network: bool) -> list[str]:
        """Return an argv that runs ``argv`` inside the sandbox."""
        ...

    def describe(self) -> str:
        ...


class NoSandbox:
    """No OS sandbox. Says so, rather than pretending."""

    def wrap(self, argv: Sequence[str], *, workdir: Path, allow_network: bool) -> list[str]:
        return list(argv)

    def describe(self) -> str:
        return ("no OS sandbox: filesystem and raw-socket access are NOT confined. The egress "
                "proxy governs HTTP clients that honour proxy variables; a raw socket bypasses "
                "it. Install a SandboxBackend (Seatbelt on macOS, bubblewrap+seccomp on Linux) "
                "for physical enforcement.")


# ---------------------------------------------------------------- the runner

@dataclass(frozen=True, slots=True)
class IsolatedResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    egress_decisions: tuple[HostDecision, ...]
    sandbox: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class IsolatedRunner:
    """Run a command in a subprocess with a clean environment behind the egress proxy."""

    def __init__(self, *, sandbox: SandboxBackend | None = None,
                 audit: Callable[..., Any] | None = None) -> None:
        self.sandbox = sandbox or NoSandbox()
        self._audit = audit
        self.runs = 0

    def run(self, argv: Sequence[str], *, workdir: Path, allowed_hosts: Iterable[str] = (),
            grants: Mapping[str, str] | None = None, timeout_s: float = 120.0,
            memory_mb: int | None = 2048, run_id: str = "", stdin: str | None = None,
            allow_private_hosts: bool = False) -> IsolatedResult:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        self.runs += 1
        hosts = list(allowed_hosts)
        try:
            proxy_cm: Any = EgressProxy(hosts, allow_private=allow_private_hosts,
                                        audit=self._audit, run_id=run_id)
        except ProxyUnavailable as exc:
            if hosts:
                # The run needs network and the kernel cannot govern it. Refusing is the only
                # honest answer: running unproxied would be the v0.3 bypass with extra steps.
                if self._audit is not None:
                    self._audit("isolated_run_refused", reason="egress proxy unavailable",
                                hosts=len(hosts), run_id=run_id)
                raise
            proxy_cm = _DeadProxy()  # no hosts wanted: point clients at a closed port
        with proxy_cm as proxy:
            env = build_child_environment(proxy_address=proxy.address, grants=grants,
                                          workdir=workdir)
            # ``hosts`` rather than ``list(allowed_hosts)``: a generator is consumed by the
            # first list() above, so re-iterating it here silently yielded False and told
            # the sandbox "no network" for a run that had been granted one.
            wrapped = self.sandbox.wrap(argv, workdir=workdir, allow_network=bool(hosts))
            started = time.time()
            timed_out = False
            # Popen rather than subprocess.run: ``run(timeout=...)`` kills only the direct
            # child. The child is started in its own session (above), and a tool that
            # spawned its own children left them running — a reviewer watched a grandchild
            # outlive the "timeout and was killed" message by a second and go on to write a
            # file. Owning the process group is the point of creating one.
            proc = subprocess.Popen(
                wrapped, cwd=str(workdir), env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                preexec_fn=_preexec(memory_mb) if sys.platform != "win32" else None,
                start_new_session=True)
            try:
                out, err = proc.communicate(input=stdin, timeout=timeout_s)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                code = 124
                _kill_process_tree(proc)
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:  # noqa: BLE001 - the tree is gone; take what we have
                    out, err = "", ""
            finally:
                # Anything the tool left behind goes with it, timeout or not: a subprocess
                # boundary that leaks background processes is not a boundary.
                _kill_process_tree(proc, grace=False)
            duration = time.time() - started
            result = IsolatedResult(
                argv=tuple(argv), exit_code=code, stdout=out[:200_000], stderr=err[:50_000],
                duration_s=duration, timed_out=timed_out,
                egress_decisions=tuple(proxy.decisions), sandbox=type(self.sandbox).__name__)
        if self._audit is not None:
            self._audit("isolated_run", argv0=argv[0] if argv else "", exit_code=code,
                        timed_out=timed_out, duration_s=round(duration, 3),
                        egress_allowed=sum(d.allowed for d in result.egress_decisions),
                        egress_refused=sum(not d.allowed for d in result.egress_decisions),
                        sandbox=result.sandbox, run_id=run_id)
        return result


def _kill_process_tree(proc: "subprocess.Popen[Any]", *, grace: bool = True) -> None:
    """Kill the child's whole process group, not only the child.

    ``start_new_session=True`` puts the child in its own process group, so one signal
    reaches everything it spawned. On Windows there are no process groups in this sense;
    ``kill()`` there terminates the child alone, which is stated rather than papered over
    (a Job Object is the equivalent and is left for the sandbox backend).
    """
    if proc.poll() is not None and not grace:
        return
    try:
        if sys.platform == "win32":  # pragma: no cover - platform specific
            proc.kill()
            return
        pgid = os.getpgid(proc.pid)
        if grace:
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return


def _preexec(memory_mb: int | None) -> Callable[[], None]:
    def fn() -> None:
        try:
            import resource

            # No core dumps (Codex process-hardening).
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if memory_mb:
                limit = memory_mb * 1024 * 1024
                for name in ("RLIMIT_AS", "RLIMIT_DATA"):
                    try:
                        resource.setrlimit(getattr(resource, name), (limit, limit))
                        break
                    except (ValueError, OSError, AttributeError):
                        continue
        except Exception:  # noqa: BLE001 - hardening is best-effort per platform
            pass
    return fn


# --------------------------------------------------- executing a component isolated

class IsolationUnavailable(RuntimeError):
    """A component had to run isolated and could not.

    Raised rather than falling back to in-process execution. The fallback is what made the
    isolation claim untrue in v0.4: the mechanism existed, the main path did not use it, and
    nothing in the record said which had run.
    """


def _safe_component(name: str) -> str:
    """One path component, with separators and traversal removed rather than trusted."""
    cleaned = re.sub(r"[^A-Za-z0-9_.@:+-]", "_", name).lstrip(".")
    return cleaned or "unnamed"


class IsolatedExecutor:
    """Executes a ``backend="subprocess"`` component through :class:`IsolatedRunner`.

    The protocol is deliberately tiny, because a component boundary that needs a framework
    is a component boundary people will route around:

    * the child receives one JSON object on **stdin** — ``{"tool", "run_id", "payload"}``;
    * it writes one JSON value on **stdout**, which becomes the tool result;
    * a non-zero exit is a ``ContractViolation`` carrying stderr, never a silent empty
      result.

    Network reach is the intersection of two declarations: the hosts the manifest asks for
    and whether the envelope permits a remote destination at all. A manifest can therefore
    narrow the run and never widen it, which is the same containment rule the authority
    lattice applies to envelopes.
    """

    def __init__(self, runner: "IsolatedRunner", *, workdir_root: Path,
                 secret_resolver: Callable[[str], str | None] | None = None) -> None:
        self.runner = runner
        self.workdir_root = Path(workdir_root)
        self.secret_resolver = secret_resolver
        self.executions = 0

    def allowed_hosts(self, manifest: Any, envelope: Any) -> list[str]:
        from ..labels import Destination

        remote = (Destination.PUBLIC_REMOTE, Destination.TRUSTED_REMOTE)
        if not any(envelope.permits_destination(d) for d in remote):
            return []
        if not any(d in remote for d in getattr(manifest, "destinations", ())):
            return []
        return [h for h in getattr(manifest, "allowed_hosts", ()) if h]

    def grants(self, manifest: Any) -> dict[str, str]:
        """Resolve only the secrets the manifest declared, and only if a resolver exists."""
        out: dict[str, str] = {}
        if self.secret_resolver is None:
            return out
        for name in getattr(manifest, "requires_secrets", ()) or ():
            value = self.secret_resolver(name)
            if value is not None:
                out[str(name)] = str(value)
        return out

    def _workdir_for(self, manifest: Any, envelope: Any) -> Path:
        """The component's working directory, proven to be inside the sandbox root.

        ``ComponentManifest`` now refuses an id that is not a safe path component, so this
        is the second of two checks rather than the only one — but it is the one that holds
        for a manifest-like object that did not come through that constructor. A component
        called ``../../escaped`` had its subprocess running outside the sandbox root
        entirely, and an absolute id would have discarded the root altogether.
        """
        root = self.workdir_root.resolve()
        run_id = str(getattr(envelope, "run_id", "") or "no_run")
        candidate = (root / _safe_component(run_id) / _safe_component(str(manifest.id)))
        resolved = candidate.resolve()
        if resolved != root and root not in resolved.parents:
            raise IsolationUnavailable(
                f"refusing to run component {manifest.id!r}: its working directory "
                f"{resolved} would fall outside the sandbox root {root}")
        return resolved

    def invoke(self, manifest: Any, payload: Any, envelope: Any) -> Any:
        import shlex

        from ..contracts import ContractViolation

        argv = shlex.split(manifest.entrypoint)
        if not argv:
            raise IsolationUnavailable(
                f"component {manifest.id!r} declares isolated execution but its entrypoint "
                "is empty")
        workdir = self._workdir_for(manifest, envelope)
        stdin = json.dumps({"tool": manifest.id, "run_id": getattr(envelope, "run_id", ""),
                            "payload": payload}, default=str)
        result = self.runner.run(
            argv, workdir=workdir, allowed_hosts=self.allowed_hosts(manifest, envelope),
            grants=self.grants(manifest), timeout_s=float(getattr(manifest, "timeout_s", 120.0)),
            memory_mb=int(getattr(manifest, "memory_mb", 2048) or 0) or None,
            run_id=getattr(envelope, "run_id", ""), stdin=stdin)
        self.executions += 1
        if result.timed_out:
            raise ContractViolation(
                f"isolated component {manifest.id!r} exceeded its {manifest.timeout_s}s "
                "timeout and was killed")
        if result.exit_code != 0:
            raise ContractViolation(
                f"isolated component {manifest.id!r} exited {result.exit_code}: "
                f"{result.stderr.strip()[:300]}")
        text = result.stdout.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            # The protocol says one JSON value on stdout. v0.5 accepted prose as
            # ``{"stdout": ...}``, which made a violated contract indistinguishable from a
            # component that meant to return text — and a component whose real output was
            # replaced by a warning on stdout would have been read as a successful result.
            raise ContractViolation(
                f"isolated component {manifest.id!r} must write one JSON value on stdout; "
                f"got {len(text)} characters that do not parse ({exc})") from exc
