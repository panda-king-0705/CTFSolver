"""Intake: accept a challenge in whatever form it ships -- a target string, a file
bundle, or a container handle -- and normalize it into a Challenge. This is the whole
end-goal promise: the operator provides the instance or the files, nothing more.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Optional

from ..models import DEFAULT_FLAG_FORMAT, Artifact, Category, Challenge, Submission, Target

# A spec-supplied flag_format is matched against large tool output, so a pathological pattern
# is a ReDoS (catastrophic backtracking). Reject over-long patterns, ones that don't compile,
# and the common nested-quantifier shapes ((a+)+, (.*)* ...), falling back to the safe default.
_SAFE_FMT_MAXLEN = 200
_NESTED_QUANT = re.compile(r"\([^)]*[*+][^)]*\)[*+]")


def safe_flag_format(pattern: Optional[str]) -> str:
    if not pattern:
        return DEFAULT_FLAG_FORMAT
    if len(pattern) > _SAFE_FMT_MAXLEN or _NESTED_QUANT.search(pattern):
        return DEFAULT_FLAG_FORMAT
    try:
        re.compile(pattern)
    except re.error:
        return DEFAULT_FLAG_FORMAT
    return pattern


_NC = re.compile(r"^\s*nc\s+(\S+)\s+(\d+)\s*$", re.IGNORECASE)
_HOSTPORT = re.compile(r"^\s*([A-Za-z0-9._-]+):(\d+)\s*$")

_MAGIC: list[tuple[bytes, str]] = [
    (b"\x7fELF", "binary"),
    (b"\x89PNG", "image"),
    (b"\xff\xd8\xff", "image"),
    (b"GIF8", "image"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcap"),
    (b"PK\x03\x04", "archive"),
    (b"\x1f\x8b", "archive"),
    (b"%PDF", "document"),
]
_SOURCE_EXT = {".py", ".c", ".cc", ".cpp", ".js", ".ts", ".php", ".rb", ".go", ".java", ".sh"}
_TEXT_EXT = {".txt", ".b64", ".hex", ".enc", ".md", ".pem", ".pub"}


def parse_target(spec: Any) -> Optional[Target]:
    """Parse a target from a string or a dict ({kind,host,port,url})."""
    if isinstance(spec, dict):
        kind = spec.get("kind")
        if kind == "tcp":
            return Target("tcp", host=spec.get("host"), port=spec.get("port"), raw=str(spec))
        if kind == "http":
            return Target("http", url=spec.get("url"), raw=str(spec))
        # infer from fields
        if spec.get("url"):
            return Target("http", url=spec["url"], raw=str(spec))
        if spec.get("host"):
            return Target("tcp", host=spec["host"], port=spec.get("port"), raw=str(spec))
        return None
    s = str(spec).strip()
    if not s:
        return None
    if "://" in s:
        return Target("http", url=s, raw=s)
    m = _NC.match(s)
    if m:
        return Target("tcp", host=m.group(1), port=int(m.group(2)), raw=s)
    m = _HOSTPORT.match(s)
    if m:
        return Target("tcp", host=m.group(1), port=int(m.group(2)), raw=s)
    if s.startswith("www.") or "/" in s:
        return Target("http", url="http://" + s, raw=s)
    return Target("tcp", host=s, raw=s)


def classify_artifact(path: str) -> Artifact:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    size = os.path.getsize(path) if os.path.exists(path) else 0
    kind = "unknown"
    sha = None
    if os.path.exists(path):
        with open(path, "rb") as f:
            head = f.read(16)
        for magic, k in _MAGIC:
            if head.startswith(magic):
                kind = k
                break
        if kind == "unknown":
            if ext in _SOURCE_EXT:
                kind = "source"
            elif ext in _TEXT_EXT or _is_text(head):
                kind = "text"
        sha = _sha256(path)
    else:
        if ext in _SOURCE_EXT:
            kind = "source"
        elif ext in _TEXT_EXT:
            kind = "text"
    return Artifact(path=path, name=name, kind=kind, size=size, sha256=sha)


def _is_text(head: bytes) -> bool:
    if not head:
        return False
    try:
        head.decode("utf-8")
        return all(b >= 9 for b in head)
    except UnicodeDecodeError:
        return False


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _infer_category(targets: list[Target], artifacts: list[Artifact]) -> Category:
    kinds = {a.kind for a in artifacts}
    has_http = any(t.kind == "http" for t in targets)
    has_tcp = any(t.kind == "tcp" for t in targets)
    if has_http:
        return Category.WEB
    if kinds & {"pcap", "image", "document"}:
        return Category.FORENSICS
    if "binary" in kinds and has_tcp:
        return Category.PWN
    if "binary" in kinds:
        return Category.REV
    if kinds & {"text", "source"} and not has_tcp:
        return Category.CRYPTO if "text" in kinds else Category.MISC
    if has_tcp:
        return Category.PWN
    return Category.UNKNOWN


def intake(
    name: str,
    *,
    targets: Optional[list[Any]] = None,
    files: Optional[list[str]] = None,
    flag_format: Optional[str] = None,
    points: int = 100,
    description: str = "",
    submission: Optional[dict] = None,
    local_instance: Optional[str] = None,
) -> Challenge:
    tgts = [t for t in (parse_target(s) for s in (targets or [])) if t]
    arts = [classify_artifact(p) for p in (files or [])]
    chal = Challenge(
        name=name, targets=tgts, artifacts=arts,
        points=points, description=description,
        local_instance=local_instance,
    )
    if flag_format:
        chal.flag_format = safe_flag_format(flag_format)
    if submission:
        chal.submission = Submission(**submission)
    chal.category_hint = _infer_category(tgts, arts)
    return chal


def intake_from_spec(spec: dict) -> Challenge:
    """Build a Challenge from a challenge.json-style dict. `files` paths may be relative
    to the spec's own directory via `_base`."""
    base = spec.get("_base", "")
    files = []
    for f in spec.get("files", []):
        files.append(os.path.join(base, f) if base and not os.path.isabs(f) else f)
    return intake(
        spec.get("name", "challenge"),
        targets=spec.get("targets", []),
        files=files,
        flag_format=spec.get("flag_format"),
        points=spec.get("points", 100),
        description=spec.get("description", ""),
        submission=spec.get("submission"),
        local_instance=spec.get("local_instance"),
    )
