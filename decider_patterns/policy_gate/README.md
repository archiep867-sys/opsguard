# Pattern: policy gate (`#policy`)

Use Strands Decider 2B to classify a proposed agent action as **safe / review / block** before the tool runs.

## Files
- `policy_question.py`: the typed `choice` question and option descriptions. Edit these for your domain.
- `policy_gate.py`: a Strands `InterventionHandler` that turns the verdict and confidence into Proceed or Deny.

## Use it
```python
from strands import Agent
from decider_patterns.policy_gate.policy_gate import PolicyGate
from opsguard.decider_client import DeciderClient

client = DeciderClient()

def classify(action: str):
    r = client.classify(action)
    return r.verdict.value.lower(), r.confidence

gate = PolicyGate(classify, tool_name="run_command", action_arg="command", min_confidence=0.5)
agent = Agent(model="<your-bedrock-model-id>", tools=[run_command], interventions=[gate])
```

## Design rules
1. The model can only make a decision stricter, never approve.
2. Low confidence on SAFE is treated as REVIEW.
3. Offline or invalid model output fails closed (`on_error = "deny"`).
4. Humans approve REVIEW outside the model's reach.
