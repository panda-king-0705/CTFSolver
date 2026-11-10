# Example traces

Structured run traces exported with `ctfsolver solve ... --trace <file>`. Load either into
the live console UI (drag-drop) to replay it.

- `repeating-xor.solved.json` — the crypto specialist generates a repeating-key XOR solver,
  runs it in the sandbox, and verifies the flag (25 events, solved).
- `admin-portal.failed.json` — a web challenge with only a remote target: the web specialist
  blocks for the container, the orchestrator escalates to misc, and the human gate denies
  (22 events, failed). Shows the escalation ladder and guardrails in action.
