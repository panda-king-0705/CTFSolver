"""Web specialist.

Live web exploitation needs scope-checked egress to the target, so the full attack
runs in the container sandbox. Offline this specialist still earns its keep: it scans
every source handout for an exposed flag (the cheap win), fingerprints the stack from
any headers/markers it can see, hunts the source for leaked secrets and dangerous sinks
(API keys, hardcoded creds, SSTI/eval), and lays out a concrete, prioritized recon +
attack plan -- optionally re-ranked by `ctx.llm('solve_strategy')` -- before cleanly
BLOCKING for the container sandbox when no flag is sitting in the open.
"""
from __future__ import annotations

import re
from typing import Optional

from ..llm.base import Message, extract_json
from ..models import Category, Outcome, Target
from .base import SolveContext, Specialist
from .registry import register
from .runner import llm_write_and_run

# --------------------------------------------------------------------------- #
# Offline signal extraction: fingerprints, secrets, dangerous sinks.
# All regexes are plain stdlib `re` -- nothing here reaches the network.
# --------------------------------------------------------------------------- #

# Stack / framework fingerprints keyed off tokens that show up in handouts
# (source, config, or captured response headers pasted into a file).
_STACK_SIGNS: list[tuple[str, str]] = [
    (r"(?i)\bflask\b|from\s+flask|werkzeug", "Flask/Werkzeug (Jinja2 SSTI, debug PIN)"),
    (r"(?i)\bdjango\b", "Django (SSTI rare, check SECRET_KEY / pickle / debug)"),
    (r"(?i)express\(\)|require\(['\"]express['\"]\)", "Node/Express (proto-pollution, NoSQLi)"),
    (r"(?i)<\?php|\$_GET|\$_POST|\$_REQUEST", "PHP (LFI/RFI, type juggling, deserialization)"),
    (r"(?i)\brails\b|ActionController", "Ruby on Rails (mass-assignment, deserialization)"),
    (r"(?i)spring-boot|org\.springframework", "Java/Spring (SpEL injection, actuator leak)"),
    (r"(?i)jinja2|render_template_string|\{\{.*\}\}", "Jinja2 template rendering (SSTI sink)"),
    (r"(?i)mysqli|mysql_query|psycopg2|sqlite3|SELECT\s.+\sFROM", "SQL backend (SQLi surface)"),
    (r"(?i)mongodb|pymongo|find\(\{", "MongoDB (NoSQL injection surface)"),
    (r"(?i)nginx", "nginx (alias traversal, misrouting)"),
    (r"(?i)apache|httpd", "Apache (htaccess, CGI, mod_* quirks)"),
]

# Header fingerprints (when a handout is a saved HTTP response / curl -i dump).
_HEADER_SIGNS: list[tuple[str, str]] = [
    (r"(?im)^server:\s*(.+)$", "Server header"),
    (r"(?im)^x-powered-by:\s*(.+)$", "X-Powered-By"),
    (r"(?im)^set-cookie:\s*([^;]+)", "Session cookie"),
    (r"(?im)^x-aspnet-version:\s*(.+)$", "ASP.NET version"),
    (r"(?im)^via:\s*(.+)$", "Proxy/Via"),
]

# Leaked-secret patterns. Deliberately conservative to limit noise.
_SECRET_SIGNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{30,}", "AWS secret key"),
    (r"gh[pousr]_[0-9A-Za-z]{30,}", "GitHub token"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Embedded private key"),
    (r"(?i)(?:secret|api[_-]?key|token|passwd|password|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "Hardcoded credential/secret"),
    (r"(?i)SECRET_KEY\s*[=:]\s*['\"][^'\"]{6,}['\"]", "Framework SECRET_KEY"),
    (r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@", "DB connection string with creds"),
    (r"(?i)(?:mysql|postgres(?:ql)?)://[^\s'\"]+:[^\s'\"]+@", "DB connection string with creds"),
]

# Dangerous sinks worth driving toward RCE/SSTI/injection.
_SINK_SIGNS: list[tuple[str, str]] = [
    (r"render_template_string\s*\(", "render_template_string -> Jinja2 SSTI"),
    (r"(?<![A-Za-z_])eval\s*\(", "eval() -> code injection"),
    (r"(?<![A-Za-z_])exec\s*\(", "exec() -> code injection"),
    (r"os\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)\s*\(", "shell exec -> command injection"),
    (r"pickle\.loads\s*\(|yaml\.load\s*\((?!.*Loader)", "unsafe deserialization"),
    (r"\.format\s*\(.*request|f['\"].*\{.*request", "format-string with user input"),
    (r"(?i)\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)", "PHP extract() -> variable injection"),
    (r"(?i)include\s*\(\s*\$_(?:GET|POST|REQUEST)|require\s*\(\s*\$_", "PHP dynamic include -> LFI/RFI"),
]


def _scan(patterns: list[tuple[str, str]], text: str, cap: int = 3) -> list[str]:
    """Return human-readable labels for every pattern that matches, de-duped."""
    hits: list[str] = []
    for pat, label in patterns:
        try:
            m = re.search(pat, text)
        except re.error:
            continue
        if not m:
            continue
        detail = ""
        if m.groups():
            grabbed = (m.group(1) or "").strip()
            if grabbed:
                detail = f": {grabbed[:60]}"
        tag = f"{label}{detail}"
        if tag not in hits:
            hits.append(tag)
        if len(hits) >= cap:
            break
    return hits


@register
class WebSpecialist(Specialist):
    category = Category.WEB
    name = "web-specialist"

    def fit_bonus(self, challenge, understanding) -> float:
        text = " ".join(understanding.recon + [understanding.subtype]).lower()
        hot = ("sqli", "xss", "ssti", "ssrf", "idor", "http", "cookie", "jwt", "upload")
        return 0.15 if any(k in text for k in hot) else 0.0

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []

        stacks: list[str] = []
        headers: list[str] = []
        secrets: list[str] = []
        sinks: list[str] = []

        # 1) Walk source handouts: cheap flag win first, then recon signals.
        for art in ctx.challenge.artifacts:
            try:
                data = ctx.sandbox.read_bytes(art.name)
            except OSError as exc:
                steps.append(f"read {art.name} -> error: {exc}")
                continue
            text = data.decode("utf-8", "ignore")

            # cheap win: flag sitting in the open
            for flag in self.find_flags(text, fmt):
                steps.append(f"grep source {art.name} -> flag")
                return self.found(flag, f"source handout {art.name}", steps, cost_usd=0.0)

            steps.append(f"reviewed source {art.name} ({len(data)} bytes)")
            stacks += [s for s in _scan(_STACK_SIGNS, text) if s not in stacks]
            headers += [h for h in _scan(_HEADER_SIGNS, text) if h not in headers]
            secrets += [s for s in _scan(_SECRET_SIGNS, text) if s not in secrets]
            sinks += [s for s in _scan(_SINK_SIGNS, text) if s not in sinks]

        # 2) Fold the fingerprint + findings into the step log.
        if stacks:
            steps.append("fingerprint: " + "; ".join(stacks))
        if headers:
            steps.append("headers: " + "; ".join(headers))
        if secrets:
            # a leaked secret is a lead, not a flag -- surface it loudly.
            steps.append("LEAKED SECRETS in source: " + "; ".join(secrets))
        if sinks:
            steps.append("DANGEROUS SINKS: " + "; ".join(sinks))

        target = next((t for t in ctx.challenge.targets if t.kind == "http"), None)
        if target:
            # the egress is in-scope; offline it just records intent (and is charged).
            try:
                await ctx.sandbox.egress(url=target.url, note="fetch web root")
                steps.append(f"GET {target.url} (in scope)")
            except Exception as exc:  # scope/connectivity -- stay graceful offline
                steps.append(f"egress note: {exc}")

        # 3) LIVE: in a real container (so the solver can actually reach the in-scope
        # target), let the model write a requests-based exploit and run it.
        if ctx.sandbox.isolated and target is not None:
            prompt = (
                "Write a COMPLETE standalone Python 3 exploit (requests, stdlib) for a CTF "
                f"web challenge at {target.url}. Drive the most likely bug to the flag and "
                "print it (flag{...}) to stdout. Read no args. Code only.\n"
                f"Fingerprint: {stacks or 'unknown'}\nSecrets: {secrets or 'none'}\n"
                f"Sinks: {sinks or 'none'}\n"
            )
            _res, flags, note = await llm_write_and_run(
                ctx, "solve_strategy", prompt,
                system="Expert web exploitation engineer. Reply with Python code only.",
                filename="web_solve.py", must_contain="requests", timeout=120)
            steps.append(note)
            if flags:
                return self.found(flags[0], "model-written web exploit run in the container", steps)

        # 4) Build an evidence-driven plan, then (cheaply) let the LLM re-rank it.
        plan = self._plan(target, stacks, secrets, sinks)
        strat = await self._ask_strategy(ctx, target, stacks, secrets, sinks)
        if strat:
            plan = strat + plan
        for p in plan:
            steps.append(f"plan: {p}")

        return self.blocked(
            "web exploitation needs the container sandbox with live egress to the target; "
            "offline recon (fingerprint/secret/sink scan) is complete and the attack plan "
            "is ready.",
            steps, hint="enable the container sandbox")

    # ------------------------------------------------------------------ #
    def _plan(self, target: Optional[Target], stacks: list[str],
              secrets: list[str], sinks: list[str]) -> list[str]:
        url = target.url if target and target.url else "<url>"
        plan = [f"fingerprint stack + headers for {url}"]
        if stacks:
            plan.append("prioritize bugs implied by fingerprint: " + "; ".join(stacks[:3]))
        if secrets:
            plan.append("try leaked secrets against the app (auth, signing, admin): "
                        + "; ".join(secrets[:3]))
        if sinks:
            plan.append("drive dangerous sink to code-exec/injection: " + "; ".join(sinks[:3]))
        plan += [
            "content discovery (feroxbuster/gobuster) for hidden routes & backups",
            "probe the usual suspects: SQLi, SSTI, auth-bypass/IDOR, SSRF, insecure deserialization",
            "inspect cookies/JWT for weak signing or tampering",
            "drive the winning bug to the flag (headless browser if the flow is stateful)",
        ]
        return plan

    async def _ask_strategy(self, ctx: SolveContext, target: Optional[Target],
                            stacks: list[str], secrets: list[str],
                            sinks: list[str]) -> list[str]:
        """Ask the frontier model to rank attack avenues. Guarded by affordability;
        tolerant of stub/garbage replies (never raises)."""
        if not ctx.ledger.can_afford(0.004, 1):
            return []
        url = target.url if target and target.url else "<unknown url>"
        prompt = (
            "You are triaging a CTF web challenge. Rank the most promising attack "
            "avenues as a JSON object: {\"ranking\": [\"...\", \"...\"]}.\n"
            f"Target: {url}\n"
            f"Stack fingerprint: {stacks or 'unknown'}\n"
            f"Leaked secrets in source: {secrets or 'none found'}\n"
            f"Dangerous sinks in source: {sinks or 'none found'}\n"
        )
        try:
            client = ctx.llm("solve_strategy")
            resp = await client.complete(
                [Message("user", prompt)],
                system="Terse CTF web exploitation strategist. Reply with JSON only.",
            )
        except Exception as exc:  # LLM unavailable / factory unbound -- stay offline-safe
            return [f"(strategy model unavailable: {exc})"]
        return _fold_strategy(resp.text)


def _fold_strategy(text: str) -> list[str]:
    """Parse an LLM strategy reply defensively into step strings. Accepts a JSON
    object/list, or falls back to plain lines. Never raises."""
    if not text or not text.strip():
        return []
    ranked: list[str] = []
    try:
        parsed = extract_json(text)
    except Exception:
        parsed = None

    def _collect(obj) -> None:
        if isinstance(obj, str):
            s = obj.strip()
            if s:
                ranked.append(s)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)
        elif isinstance(obj, dict):
            # ignore pure stub acks like {"ok": true, "stub": true}
            for key in ("ranking", "strategies", "plan", "avenues", "steps", "attacks"):
                if key in obj:
                    _collect(obj[key])

    if parsed is not None:
        _collect(parsed)

    if not ranked:
        # no usable structure -- take the first few non-empty lines verbatim.
        for line in text.splitlines():
            line = line.strip(" -*\t")
            if line and not line.startswith("{") and not line.startswith("}"):
                ranked.append(line)
            if len(ranked) >= 5:
                break

    return [f"LLM strategy: {r}" for r in ranked[:5]]
