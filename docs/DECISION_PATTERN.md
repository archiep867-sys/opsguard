# Reusable decision pattern: the policy gate (`#policy`)

A drop-in recipe for any Strands agent that can call risky tools. A small decision model
labels every proposed tool call SAFE, REVIEW, or BLOCK **with a confidence score** before the
tool runs. Plain Python then decides what to do, so the model classifies and the code decides.

## 1. The typed question and option set

One Strands Decider `choice` question, sent with the proposed call as the state
(`opsguard/decider_client.py`):

```json
{
  "state": {"proposed_command": "kubectl scale deployment web --replicas=5", "execution": "simulation only"},
  "questions": {"verdict": {
    "type": "choice",
    "instructions": "An AI agent proposes to run this DevOps command. Classify how risky it is to allow.",
    "criteria": {
      "safe":   "Read-only inspection that changes nothing, e.g. listing, describing, status, logs, get.",
      "review": "Changes state but is reversible or bounded. A human must approve first.",
      "block":  "Destructive, irreversible, or dangerous. Must not run."
    }
  }}
}
```

The server returns `{"type": "choice", "choice": "...", "probabilities": {...}, "confidence": 0.0-1.0}`.
The option descriptions carry most of the signal, so write them as carefully as the question.
Swap the three options for any ladder of your own (for example `allow / ask / deny`).

## 2. The wiring: a Strands `InterventionHandler`

`opsguard/gate.py` implements `before_tool_call`, which runs before Strands executes a tool:

```python
class OpsGuardGate(InterventionHandler):
    name = "opsguard-gate"
    on_error = "deny"                        # fail closed if the handler itself breaks

    def before_tool_call(self, event, **kwargs):
        command = event.tool_use["input"]["command"]
        pipeline = decide(command, self._decider)          # rules floor + Decider vote
        if pipeline.final.decision is Decision.BLOCK:
            return Deny(reason="BLOCKED: ...")
        if pipeline.final.decision is Decision.REVIEW and not self.store.approved(...):
            return Deny(reason="REVIEW required: a person must approve in the dashboard")
        return Proceed()
```

Attach it with `Agent(model=..., tools=[run_command], interventions=[gate])`.

## 3. The rules that make it safe to reuse

1. **A deterministic floor.** Obvious destructive commands are blocked in code and the model is
   never consulted. The model can only make a verdict stricter.
2. **One bounded exception.** A command that is merely *unknown* may be routed to human REVIEW
   when the model is confident; it can never become SAFE through a model vote.
3. **Low confidence escalates to a person.** A shaky BLOCK vote becomes REVIEW, and an unknown
   command with low confidence stays blocked. Tune the threshold with `eval/run_eval.py`.
4. **Approval happens outside the model.** Human approvals live in an `ApprovalStore` that only
   dashboard code can write; they are bound to one command and target and are single-use.
5. **Fail closed.** An offline or invalid Decider response never relaxes a verdict.

## 4. How to use it in your own agent

The smallest copy-paste version lives in `decider_patterns/policy_gate/` (question + handler,
no OpsGuard internals). The steps below describe the fuller OpsGuard version.

1. Copy `opsguard/decider_client.py`, `opsguard/decision_pipeline.py` and `opsguard/gate.py`.
2. Replace the rule table in `opsguard/safety_engine.py` with your own hard rules.
3. Edit the three option descriptions in `decider_client.py` for your domain.
4. Label 100 examples like `eval/commands.jsonl`, run `python eval/run_eval.py`, and set
   `OPSGUARD_MIN_MODEL_CONFIDENCE` from the calibration table.
5. Start the model: `strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8099`.

## 5. Limits

The model is experimental and 2B parameters small; the labelled set is small; confidence is
the server's normalised score, not a probability of being correct. Use it as a gate in front of
human review, not as the only control. Nothing in OpsGuard executes real commands.
