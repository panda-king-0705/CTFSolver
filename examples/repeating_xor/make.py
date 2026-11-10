"""A challenge the in-process single-byte ladder can't solve: the flag is XOR'd with a
repeating multi-byte key. The crypto specialist's LIVE path recovers it by GENERATING a
solver and RUNNING it in the sandbox (the generate->run->observe loop)."""
import json
import os

FLAG = "flag{generated_solvers_run_in_the_sandbox}"
KEY = b"KEY"  # 3-byte repeating key; <= len("flag{") so a known-plaintext crib recovers it

here = os.path.dirname(os.path.abspath(__file__))
fb = FLAG.encode()
cipher = bytes(fb[i] ^ KEY[i % len(KEY)] for i in range(len(fb)))
with open(os.path.join(here, "cipher.txt"), "wb") as f:
    f.write(cipher)

spec = {
    "name": "repeating-xor",
    "files": ["cipher.txt"],
    "flag_format": r"flag\{[^}]+\}",
    "points": 150,
    "description": "Multi-byte key. Single-byte brute won't cut it.",
    "submission": {"kind": "regex", "extra": {"answer": FLAG}},
}
with open(os.path.join(here, "challenge.json"), "w") as f:
    json.dump(spec, f, indent=2)
print("wrote cipher.txt and challenge.json; flag =", FLAG)
