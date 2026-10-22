"""OpsGuard enterprise-style security dashboard; it remains simulation-only."""

from __future__ import annotations

import csv
import io
import json
from datetime import date

import pandas as pd
import streamlit as st

from opsguard.approval import approve
from opsguard.audit import AuditEvent, AuditLog
from opsguard.bedrock_client import BEDROCK_DISABLED, BedrockClient
from opsguard.decider_client import DeciderClient
from opsguard.decision_pipeline import PipelineDecision, decide
from opsguard.safety_engine import Decision, Evaluation, POLICY_RULES
from opsguard.simulator import simulate

AUDIT = AuditLog()
EXAMPLES = {"Read cluster pods": "kubectl get pods -n production", "Deploy workload": "kubectl apply -f deployment.yaml", "Delete files": "rm -rf /", "Inspect Git state": "git status"}
SCENARIOS = {
    "Safe Kubernetes inspection": ("kubectl get pods -n staging", "staging", "pods"),
    "Scale a deployment": ("kubectl scale deployment web --replicas=5 -n staging", "staging", "web"),
    "Delete a namespace": ("kubectl delete namespace production", "production", "production"),
    "Suspicious IAM change": ("aws iam attach-user-policy --user-name ci-bot --policy-arn arn:aws:iam::aws:policy/AdministratorAccess", "production", "ci-bot"),
    "Open an S3 bucket": ("aws s3api put-bucket-acl --bucket reports --acl public-read", "production", "reports"),
    "Unknown tool (Decider triage)": ("docker ps", "staging", "docker"),
}
RISK_COLORS = {"SAFE": "#33c38e", "REVIEW": "#f6b84b", "BLOCK": "#ef6b73"}


def _configure() -> None:
    st.set_page_config(page_title="OpsGuard | Command Security", page_icon="OG", layout="wide")
    st.markdown("""<style>
    .stApp {background:#07111f;color:#e7edf7} [data-testid="stSidebar"] {background:#0a1829;border-right:1px solid #1e344d}
    [data-testid="stSidebar"] * {color:#dce8f5}.og-kicker {color:#72d7ff;font-size:.78rem;font-weight:700;letter-spacing:.11em}
    .og-title {font-size:2rem;font-weight:700;margin:0 0 .2rem}.og-subtitle,.og-muted {color:#a9bbcf;margin-bottom:1.3rem}
    .og-card {background:#0d1d30;border:1px solid #1b3651;border-radius:10px;padding:1rem 1.1rem;min-height:96px}
    .og-card-label {font-size:.75rem;color:#9bb0c7;letter-spacing:.06em;text-transform:uppercase}.og-card-value {font-size:1.7rem;font-weight:700;margin-top:.35rem}
    .og-banner {background:#13263a;border:1px solid #2c5275;color:#cbe9ff;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0 1rem}
    .og-decision {border-radius:10px;padding:1rem 1.2rem;color:#07111f;font-weight:800;font-size:1.2rem}
    div[data-testid="stDataFrame"] {border:1px solid #1b3651;border-radius:8px}</style>""", unsafe_allow_html=True)


def _header(title: str, subtitle: str) -> None:
    st.markdown('<div class="og-kicker">OPS GUARD · LOCAL CONTROL PLANE</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="og-title">{title}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="og-subtitle">{subtitle}</div>', unsafe_allow_html=True)
    st.markdown('<div class="og-banner">SIMULATION ONLY · No submitted command can execute from this application.</div>', unsafe_allow_html=True)


def _event_rows(events: list[AuditEvent]) -> list[dict[str, object]]:
    return [{"Time (UTC)": e.created_at.replace("T", " ")[:19], "Command": e.command[:140], "Decision": e.decision, "Environment": e.environment or "—", "Resource": e.resource_name or "—", "Reasons": "; ".join(json.loads(e.reasons)), "Approval": e.approval_outcome or "—", "Simulation": "Recorded" if e.simulation_result else "—"} for e in events]


def _status(client: DeciderClient) -> tuple[str, str]:
    status = client.health()
    return status, ("Local Decider responding" if status == "available" else "Offline; deterministic policy remains active")


def overview(client: DeciderClient) -> None:
    _header("Security overview", "Local command-risk telemetry from the OpsGuard audit store.")
    metrics = AUDIT.metrics()
    status, description = _status(client)
    columns = st.columns(5)
    items = [("Audited evaluations", metrics["total"], "#dce8f5"), ("Safe", metrics["SAFE"], RISK_COLORS["SAFE"]), ("Review", metrics["REVIEW"], RISK_COLORS["REVIEW"]), ("Blocked", metrics["BLOCK"], RISK_COLORS["BLOCK"]), ("Local Decider", status.upper(), "#72d7ff")]
    for column, (label, value, color) in zip(columns, items, strict=True):
        column.markdown(f'<div class="og-card"><div class="og-card-label">{label}</div><div class="og-card-value" style="color:{color}">{value}</div></div>', unsafe_allow_html=True)
    st.caption(description)
    left, right = st.columns((1, 2))
    with left:
        st.subheader("Risk distribution")
        st.bar_chart(pd.DataFrame({"Events": [metrics["SAFE"], metrics["REVIEW"], metrics["BLOCK"]]}, index=["SAFE", "REVIEW", "BLOCK"]), color="#37a9d6", horizontal=True)
    with right:
        st.subheader("Recent security events")
        events = AUDIT.events(limit=8)
        if events:
            st.dataframe(pd.DataFrame(_event_rows(events)), width="stretch", hide_index=True)
        else:
            st.info("No evaluations recorded. Use the Command Playground to create the first local audit event.")


def _evaluate(command: str, environment: str, resource: str, client: DeciderClient) -> None:
    pipeline = decide(command, client)
    evaluation = pipeline.final
    st.session_state.update(evaluation=evaluation, pipeline=pipeline, evaluation_context=(command, environment, resource), approval=None, decider_available=pipeline.decider_status == "DECIDER_USED", model_detail=pipeline.decider_status)
    event_id = AUDIT.record(evaluation, decider_available=pipeline.decider_status == "DECIDER_USED", environment=environment, resource_name=resource, pipeline=pipeline)
    st.session_state.update(audit_event_id=event_id, explanation=None, explanation_context=None)


def _confidence_panel(pipeline: PipelineDecision) -> None:
    """Show the Decider's real probabilities and confidence (never invented numbers)."""
    if not pipeline.model_probabilities:
        return
    st.markdown("**Strands Decider vote**")
    for label in ("safe", "review", "block"):
        value = pipeline.model_probabilities.get(label, 0.0)
        color = RISK_COLORS[label.upper()]
        st.markdown(f'<div style="display:flex;align-items:center;gap:.6rem;margin:.15rem 0"><span style="width:4.5rem;font-size:.8rem;color:#a9bbcf">{label.upper()}</span>'
                    f'<div style="flex:1;background:#0d1d30;border-radius:6px;height:12px"><div style="width:{value * 100:.1f}%;background:{color};height:12px;border-radius:6px"></div></div>'
                    f'<span style="width:3.2rem;text-align:right;font-size:.8rem">{value:.2f}</span></div>', unsafe_allow_html=True)
    latency = f"{pipeline.latency_ms:.0f} ms" if pipeline.latency_ms is not None else "n/a"
    st.caption(f"Confidence {pipeline.model_confidence:.2f} · Decider latency {latency} · measured on this machine")


def _explain_panel(evaluation: Evaluation, pipeline: PipelineDecision, context: tuple[str, str, str]) -> None:
    """Optional Bedrock explanation; it can never change the verdict above."""
    bedrock = BedrockClient()
    with st.expander("Explain this decision in plain words (optional, Amazon Bedrock)"):
        state = bedrock.status()
        if state == BEDROCK_DISABLED:
            st.caption("Bedrock is off (OPSGUARD_BEDROCK_ENABLED is not true). A template explanation is available without any AI model.")
        question = st.text_input("What would you like explained?", value="What will this command do and what should I do next?", key="explain_question")
        if st.button("Explain"):
            result = bedrock.explain(pipeline, question, environment=context[1], resource_name=context[2])
            st.session_state.update(explanation=result, explanation_context=context)
            if st.session_state.get("audit_event_id"):
                AUDIT.attach_explanation(st.session_state["audit_event_id"], result)
        result = st.session_state.get("explanation")
        if result is not None and st.session_state.get("explanation_context") == context:  # never show another command's text
            label = {"bedrock": f"AI-generated by Amazon Bedrock ({result.model_id})", "local_template": "Template explanation (not AI-generated)"}[result.source]
            st.caption(f"{label} · status {result.status}" + (f" · {result.error_category}" if result.error_category else "") + f" · authoritative verdict: {evaluation.decision.value}")
            st.markdown(result.text)


def playground(client: DeciderClient) -> None:
    _header("Command Security Playground", "Evaluate a proposed DevOps command. Approval enables a simulation record only—never execution.")
    st.markdown("**One-click scenarios**")
    columns = st.columns(3)
    for index, (label, (scenario_command, scenario_env, scenario_resource)) in enumerate(SCENARIOS.items()):
        if columns[index % 3].button(label, key=f"scenario_{index}", width="stretch"):
            st.session_state.update(command_input=scenario_command, environment_input=scenario_env, resource_input=scenario_resource)
            with st.spinner("Evaluating…"):
                _evaluate(scenario_command, scenario_env, scenario_resource, client)
    choice = st.selectbox("Load an example", ["Custom", *EXAMPLES], key="example")
    if choice != "Custom" and st.session_state.get("loaded_example") != choice:
        st.session_state["command_input"], st.session_state["loaded_example"] = EXAMPLES[choice], choice
    command = st.text_area("Proposed command", key="command_input", placeholder="kubectl get pods -n production", height=110)
    first, second = st.columns(2)
    environment = first.text_input("Target environment", key="environment_input", placeholder="production")
    resource = second.text_input("Exact resource name", key="resource_input", placeholder="api-deployment")
    if st.button("Evaluate command", type="primary", width="stretch"):
        with st.spinner("Applying deterministic safety policy…"):
            _evaluate(command, environment, resource, client)
    evaluation: Evaluation | None = st.session_state.get("evaluation")
    pipeline: PipelineDecision | None = st.session_state.get("pipeline")
    if evaluation is None:
        st.info("Enter a command or load an example. Unknown and malformed commands fail closed.")
        return
    context_matches = (command, environment, resource) == st.session_state.get("evaluation_context")
    if not context_matches:
        st.warning("Command or target changed after evaluation. Re-evaluate before approval or simulation.")
        st.session_state["approval"] = None
    st.markdown(f'<div class="og-decision" style="background:{RISK_COLORS[evaluation.decision.value]}">{evaluation.decision.value} · {evaluation.category.upper()}</div>', unsafe_allow_html=True)
    one, two = st.columns((2, 1))
    with one:
        st.subheader("Decision details")
        for reason in evaluation.reasons:
            st.write(f"• {reason}")
        next_step = {Decision.SAFE: "Record a simulation.", Decision.REVIEW: "Provide exact resource confirmation for a simulation.", Decision.BLOCK: "Revise the request; BLOCK decisions cannot be approved."}[evaluation.decision]
        st.write(f"**Recommended next step:** {next_step}")
    with two:
        st.subheader("Classification sources")
        st.metric("Deterministic policy", pipeline.deterministic.decision.value if pipeline else "—")
        st.caption(f"Decider: {pipeline.decider_status if pipeline else 'not evaluated'}")
        if pipeline and pipeline.model_verdict:
            st.caption(f"Model verdict: {pipeline.model_verdict.value}; confidence: {pipeline.model_confidence:.2f}")
        elif pipeline and pipeline.failure_reason:
            st.caption(pipeline.failure_reason)
        st.caption("Hard blocks never call the model. Known commands can only be tightened by the Decider. Unknown commands go to human REVIEW at best, never SAFE.")
        if pipeline:
            _confidence_panel(pipeline)
    st.code(evaluation.normalized_command or evaluation.command, language="bash")
    if not context_matches:
        return
    _explain_panel(evaluation, pipeline, (command, environment, resource))
    if evaluation.decision is Decision.BLOCK:
        st.error("Blocked commands cannot be approved or simulated.")
    elif evaluation.decision is Decision.SAFE:
        if st.button("Record safe simulation"):
            result = simulate(evaluation, environment=environment, resource_name=resource)
            AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="not-required", simulation_result=result.message, environment=environment, resource_name=resource, pipeline=pipeline)
            st.success(result.message)
    else:
        st.subheader("Human approval required")
        confirmation = st.text_input("Type the exact resource name to approve this simulation", key="resource_confirmation")
        if st.button("Approve and record simulation"):
            try:
                approval = approve(evaluation, environment, resource, confirmation)
                result = simulate(evaluation, approval, environment=environment, resource_name=resource)
                AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="approved", confirmation_outcome="matched", simulation_result=result.message, environment=environment, resource_name=resource, pipeline=pipeline)
                st.success(result.message)
            except ValueError as exc:
                AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="denied", confirmation_outcome="not-matched", environment=environment, resource_name=resource, pipeline=pipeline)
                st.error(str(exc))


def agent_console(client: DeciderClient) -> None:
    """A Bedrock-powered Strands agent whose every tool call passes through the OpsGuard gate."""
    _header("Agent console", "An Amazon Bedrock agent proposes commands; Strands Decider and policy gate every one. Nothing is executed.")
    bedrock = BedrockClient()
    if not bedrock.enabled or not bedrock.model_id or not bedrock.region:
        st.warning("Set OPSGUARD_BEDROCK_ENABLED=true, OPSGUARD_BEDROCK_MODEL_ID and AWS_REGION, then restart (see README).")
        return
    from opsguard.agent import build_agent
    from opsguard.gate import ApprovalStore, OpsGuardGate

    if "gate" not in st.session_state:
        gate = OpsGuardGate(client, ApprovalStore(), AUDIT)
        st.session_state.update(gate=gate, agent=build_agent(gate), chat=[])
    gate: OpsGuardGate = st.session_state["gate"]
    for role, text in st.session_state["chat"]:
        st.chat_message(role).write(text)
    prompt = st.chat_input("Ask the agent to do something, e.g. 'scale web to 5 replicas in staging'")
    if prompt:
        st.session_state["chat"].append(("user", prompt))
        with st.spinner("Agent is working…"):
            try:
                reply = str(st.session_state["agent"](prompt))
            except Exception as exc:  # noqa: BLE001 - show a safe category, never raw AWS text
                reply = f"The agent could not complete the request ({BedrockClient.categorize_error(exc)})."
        st.session_state["chat"].append(("assistant", reply))
        st.rerun()
    st.subheader("Decision trail")
    if gate.log:
        st.dataframe(pd.DataFrame(gate.log[::-1]), width="stretch", hide_index=True)
    else:
        st.caption("Each tool call the agent proposes appears here with its verdict, Decider confidence and gate latency.")
    st.subheader("Human approvals")
    pending = gate.store.pending()
    if not pending:
        st.caption("No approvals waiting. Commands that need review appear here for a person to approve.")
    for request in pending:
        with st.container(border=True):
            st.write(f"**Request #{request.request_id}** · `{request.command}` · {request.environment or 'no environment'} / {request.resource_name or 'no resource'}")
            confirmation = st.text_input("Type the exact resource name to approve", key=f"confirm_{request.request_id}")
            approve_col, reject_col = st.columns(2)
            if approve_col.button("Approve", key=f"approve_{request.request_id}"):
                try:
                    gate.store.grant(request.request_id, confirmation)
                    st.success("Approved for one simulation. Tell the agent to retry.")
                except ValueError as exc:
                    st.error(str(exc))
            if reject_col.button("Reject", key=f"reject_{request.request_id}"):
                gate.store.reject(request.request_id)
                st.rerun()


def policy_details() -> None:
    _header("Policy and decision details", "Rules are derived from the local deterministic evaluator; optional model output is not policy.")
    query = st.text_input("Filter policy rules", placeholder="Search identifiers, levels, or descriptions")
    rows = [{"Rule": rule, "Policy": description, "Decision": level, "Coverage": coverage} for rule, description, level, coverage in POLICY_RULES]
    if query:
        rows = [row for row in rows if query.lower() in " ".join(map(str, row.values())).lower()]
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.info("The Decider can tighten a verdict, or route an unknown command to human review. It never makes a command SAFE, and Bedrock text never changes a verdict.")


def audit_explorer() -> None:
    _header("Audit explorer", "Actual records from the local SQLite audit store. New records redact common secret assignments.")
    all_events = AUDIT.events(limit=500)
    environments = sorted({event.environment for event in all_events if event.environment})
    first, second, third = st.columns(3)
    decision = first.selectbox("Decision", ["ALL", "SAFE", "REVIEW", "BLOCK"])
    environment = second.selectbox("Environment", ["All environments", *environments])
    search = third.text_input("Search commands, reasons, resources")
    events = AUDIT.events(decision=decision, environment=None if environment == "All environments" else environment, search=search or None, limit=500)
    minimum = date.fromisoformat(events[-1].created_at[:10]) if events else date.today()
    dates = st.date_input("Recorded date range (UTC)", value=(minimum, date.today()))
    if isinstance(dates, tuple) and len(dates) == 2:
        events = [event for event in events if dates[0] <= date.fromisoformat(event.created_at[:10]) <= dates[1]]
    rows = _event_rows(events)
    if not rows:
        st.info("No audit records match these filters.")
        return
    frame = pd.DataFrame(rows)
    st.dataframe(frame, width="stretch", hide_index=True)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
    writer.writeheader(); writer.writerows(rows)
    st.download_button("Export filtered CSV", data=buffer.getvalue(), file_name="opsguard-audit.csv", mime="text/csv")


def system_status(client: DeciderClient) -> None:
    _header("System status", "Actual local capability status. No cloud account, Kubernetes cluster, database, or execution adapter is connected.")
    status, description = _status(client)
    st.dataframe(pd.DataFrame([
        {"Capability": "Deterministic command policy", "Status": "Enabled", "Detail": "Offline SAFE / REVIEW / BLOCK classification"},
        {"Capability": "Human simulation approval", "Status": "Enabled", "Detail": "Exact resource confirmation for REVIEW"},
        {"Capability": "SQLite audit log", "Status": "Enabled", "Detail": "Local parameterized writes"},
        {"Capability": "Local Strands Decider", "Status": status, "Detail": description},
        {"Capability": "Amazon Bedrock explanations and agent", "Status": BedrockClient().status(), "Detail": "Optional; configuration state only, no AWS call is made on this page"},
        {"Capability": "Command execution", "Status": "Disabled", "Detail": "No shell or infrastructure adapter exists"},
    ]), width="stretch", hide_index=True)
    st.subheader("Prototype limitations")
    st.markdown("- SQLite audit logs are local and not tamper-evident.\n- Approval is not identity verification or production authorization.\n- Do not submit credentials, secrets, or tokens.\n- The local Decider is optional; offline, known commands use deterministic policy and unknown commands stay blocked.\n- Bedrock text is an explanation only; a model request sends sanitized decision context to AWS.")


def main() -> None:
    _configure(); client = DeciderClient()
    with st.sidebar:
        st.markdown("## OpsGuard"); st.caption("Command safety control plane")
        page = st.radio("Navigation", ["Security Overview", "Command Playground", "Agent Console", "Policy Details", "Audit Explorer", "System Status"])
        st.divider(); st.caption("Simulation-only prototype")
    {"Security Overview": lambda: overview(client), "Command Playground": lambda: playground(client), "Agent Console": lambda: agent_console(client), "Policy Details": policy_details, "Audit Explorer": audit_explorer, "System Status": lambda: system_status(client)}[page]()


if __name__ == "__main__":
    main()
