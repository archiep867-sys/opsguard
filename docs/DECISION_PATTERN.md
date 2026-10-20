# OpsGuard decision pattern

Every command an agent proposes passes through `OpsGuardGate` before Strands runs the tool.

| Verdict | Gate action |
|---------|-------------|
| SAFE    | Proceed (tool records a simulation only) |
| REVIEW  | Deny until a human types the exact resource name; approval is single-use and bound to one command and target |
| BLOCK   | Deny, with a plain-language reason for the agent to explain |

## Rules
1. Deterministic policy runs first. Destructive, obfuscated and malformed commands are blocked without calling the model.
2. The Strands Decider can only make a verdict stricter. The one exception: an unknown command may move from BLOCK to REVIEW when the model is confident. It never becomes SAFE.
3. A low-confidence BLOCK vote on a known command becomes REVIEW, so a person decides.
4. Offline or invalid model output never loosens a verdict.
5. The agent cannot approve anything. Approvals live in `ApprovalStore`, and only human-facing code calls `grant`.
6. Audit records and anything sent to Bedrock pass through the shared redactor in `opsguard/redaction.py`.
7. Nothing executes. `simulator.py` has no process-execution API.

## Limits
Pattern-based redaction cannot catch every secret. SQLite audit logs are local and not tamper-evident. Approval is not identity verification.
