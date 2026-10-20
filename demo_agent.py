"""Terminal demo: Bedrock agent -> OpsGuard gate -> human approval in this terminal. Simulation only."""

from opsguard.agent import build_agent
from opsguard.audit import AuditLog
from opsguard.decider_client import DeciderClient
from opsguard.gate import OpsGuardGate

gate = OpsGuardGate(DeciderClient(), audit=AuditLog())
agent = build_agent(gate)

while True:
    prompt = input("\nYou> ").strip()
    if prompt.lower() in {"exit", "quit"}:
        break
    print("\nAgent>", agent(prompt))
    for req in gate.store.pending():
        print(f"\n[APPROVAL #{req.request_id}] {req.command}  env={req.environment}  resource={req.resource_name}")
        typed = input(f"Type '{req.resource_name}' to approve, or press Enter to reject: ")
        if not typed:
            gate.store.reject(req.request_id)
            print("Rejected.")
            continue
        try:
            gate.store.grant(req.request_id, typed)
        except ValueError as exc:
            print("Not approved:", exc)
            continue
        print("\nAgent>", agent(f"A human approved request #{req.request_id}. Retry the same command exactly."))
