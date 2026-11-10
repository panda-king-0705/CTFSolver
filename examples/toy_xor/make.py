"""Generate a self-contained toy challenge the solver can crack fully offline:
the flag is single-byte XOR'd then base64-encoded. No network, no external tools --
it exercises the whole pipeline (intake -> triage -> route -> crypto solve -> verify
-> learn) and ends in a verified flag."""
from __future__ import annotations

import base64
import json
import os

FLAG = "flag{x0r_4nd_base64_are_not_crypto}"
KEY = 0x5C

here = os.path.dirname(os.path.abspath(__file__))
xored = bytes(b ^ KEY for b in FLAG.encode())
cipher_b64 = base64.b64encode(xored)

with open(os.path.join(here, "cipher.b64"), "wb") as f:
    f.write(cipher_b64)

spec = {
    "name": "toy-xor",
    "files": ["cipher.b64"],
    "flag_format": r"flag\{[^}]+\}",
    "points": 100,
    "description": "A warm-up. The ciphertext is base64 of something simple.",
    "submission": {"kind": "regex", "extra": {"answer": FLAG}},
}
with open(os.path.join(here, "challenge.json"), "w") as f:
    json.dump(spec, f, indent=2)

print("wrote", os.path.join(here, "cipher.b64"))
print("wrote", os.path.join(here, "challenge.json"))
print("cipher:", cipher_b64.decode())
