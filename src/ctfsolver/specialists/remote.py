"""Solve a live instance you were handed as `nc host port` -- no binary, just the socket.

Many CTF instances are interactive: the service prints a banner/prompt and the flag
falls out of the right exchange (sometimes it is printed on connect). This drives the
same generate -> run -> observe loop the rest of the solver uses, but over the network:

1. **First contact** -- a generated stdlib-`socket` script connects, reads the banner,
   and (optionally) sends a few generic probes, printing the whole transcript. If the
   flag is already there, we are done. Deterministic, so it works offline and in tests.
2. **Scripted solve** -- hand that transcript to the model and have it WRITE a complete
   interactive solver (socket/pwntools) for the observed protocol; run it; read the flag.

Everything runs *inside the sandbox*, so under `--container` the egress firewall confines
the connection to the challenge's own target (scope -> `sandbox/egress.py`). The script
only ever connects to the host:port it was given, which is the authorized instance.
"""
from __future__ import annotations

from typing import Optional

from ..models import Target
from .base import SolveContext
from .runner import extract_flags, llm_write_and_run, run_script

# Conservative generic probes for first contact: a bare newline, then a few of the most
# common "pick an option / say yes" tokens. Enough to trip flag-on-prompt services; the
# model-written solver handles anything structured.
DEFAULT_PROBES = ["", "1", "y"]

_PROBE_TEMPLATE = '''\
import socket, sys

host = sys.argv[1]
port = int(sys.argv[2])
sends = {sends!r}
connect_timeout = {connect_timeout!r}
read_timeout = {read_timeout!r}

def drain(sock, buf):
    sock.settimeout(read_timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.append(chunk)
    except Exception:
        pass

buf = []
try:
    sock = socket.create_connection((host, port), timeout=connect_timeout)
except Exception as exc:
    sys.stdout.write("CONNECT_ERROR: %s\\n" % exc)
    sys.exit(2)

drain(sock, buf)
for line in sends:
    data = line if line.endswith("\\n") else line + "\\n"
    try:
        sock.sendall(data.encode())
    except Exception as exc:
        sys.stdout.write("SEND_ERROR: %s\\n" % exc)
        break
    drain(sock, buf)

try:
    sock.close()
except Exception:
    pass
sys.stdout.write(b"".join(buf).decode("latin-1"))
'''


def _build_probe(sends: list[str], connect_timeout: float, read_timeout: float) -> str:
    return _PROBE_TEMPLATE.format(
        sends=sends, connect_timeout=connect_timeout, read_timeout=read_timeout
    )


async def first_contact(
    ctx: SolveContext,
    remote: Target,
    *,
    sends: Optional[list[str]] = None,
    connect_timeout: float = 8.0,
    read_timeout: float = 3.0,
) -> tuple[str, list[str]]:
    """Connect, read the banner (and send `sends` if given), returning (transcript, flags)."""
    source = _build_probe(sends or [], connect_timeout, read_timeout)
    fname = "first_contact.py" if not sends else "probe.py"
    res, _flags = await run_script(
        ctx, fname, source,
        args=[remote.host or "", str(remote.port or 0)],
        timeout=connect_timeout + read_timeout * (len(sends or []) + 2) + 10,
    )
    transcript = res.stdout or ""
    flags = extract_flags(ctx, transcript)
    return transcript, flags


async def solve_remote(ctx: SolveContext, remote: Target) -> tuple[Optional[str], list[str]]:
    """Try to solve a live instance over the socket. Returns (flag | None, steps). Any
    solver the model writes is captured in the trace by `run_script`, so the writeup
    reproduces it without us passing the source back here."""
    steps: list[str] = []
    if not remote.host or not remote.port:
        return None, steps

    where = f"{remote.host}:{remote.port}"
    ctx.trace.note("solve", f"first contact with {where}")

    # 1) connect + read the banner
    transcript, flags = await first_contact(ctx, remote)
    if transcript.startswith("CONNECT_ERROR"):
        steps.append(f"connect {where} -> {transcript.strip()}")
        return None, steps
    steps.append(f"connected {where}; read {len(transcript)} bytes of banner")
    if flags:
        steps.append("flag present in the banner on connect")
        return flags[0], steps

    # 1b) a couple of generic probes, in case the flag is one trivial prompt away
    transcript2, flags = await first_contact(ctx, remote, sends=DEFAULT_PROBES)
    if flags:
        steps.append(f"flag after generic probes {DEFAULT_PROBES}")
        return flags[0], steps
    banner = (transcript2 or transcript)[:1500]

    # 2) let the model write a full interactive solver from what the service said
    if ctx.ledger.can_afford(0.01, 2):
        prompt = (
            "You are given a live CTF service reachable over TCP. Write a COMPLETE Python 3 "
            "solver that connects to it and prints the flag (matching "
            f"{ctx.challenge.flag_format!r}) to stdout. Connect to HOST=sys.argv[1] and "
            "PORT=int(sys.argv[2]). Use the stdlib `socket` module (or pwntools if you "
            "prefer). Read prompts, respond as the protocol requires, and print everything "
            "you receive. Output ONLY the code.\n\n"
            f"Challenge: {ctx.challenge.name}\n"
            f"Description: {ctx.challenge.description or '(none)'}\n"
            f"Transcript of first contact (latin-1):\n{banner}\n"
        )
        _res, flags, note = await llm_write_and_run(
            ctx, "solve_scripting", prompt,
            system="Expert CTF player. You write correct, self-contained solver scripts. Code only.",
            filename="remote_solve.py",
            args=[remote.host, str(remote.port)],
            min_len=60, must_contain="", budget_usd=0.01, timeout=120.0,
        )
        steps.append(note)
        if flags:
            steps.append("model-written interactive solver recovered the flag")
            return flags[0], steps
    else:
        steps.append("insufficient budget for a model-written interactive solver")

    steps.append("no flag from banner, generic probes, or a scripted solve")
    return None, steps
