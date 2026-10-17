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
from opsguard.decider_client import DeciderClient, DeciderUnavailable
from opsguard.safety_engine import Decision, Evaluation, POLICY_RULES, evaluate_command
from opsguard.simulator import simulate

AUDIT = AuditLog()
EXAMPLES = {"Read cluster pods": "kubectl get pods -n production", "Deploy workload": "kubectl apply -f deployment.yaml", "Delete files": "rm -rf /", "Inspect Git state": "git status"}
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
            st.dataframe(pd.DataFrame(_event_rows(events)), use_container_width=True, hide_index=True)
        else:
            st.info("No evaluations recorded. Use the Command Playground to create the first local audit event.")


def _evaluate(command: str, environment: str, resource: str, client: DeciderClient) -> None:
    evaluation = evaluate_command(command)
    available, detail = False, "AI classification unavailable; deterministic policy was used."
    try:
        model = client.classify(command)
        available, detail = model.available, model.detail
    except DeciderUnavailable as exc:
        detail = str(exc)
    st.session_state.update(evaluation=evaluation, evaluation_context=(command, environment, resource), approval=None, decider_available=available, model_detail=detail)
    AUDIT.record(evaluation, decider_available=available, environment=environment, resource_name=resource)


def playground(client: DeciderClient) -> None:
    _header("Command Security Playground", "Evaluate a proposed DevOps command. Approval enables a simulation record only—never execution.")
    choice = st.selectbox("Load an example", ["Custom", *EXAMPLES], key="example")
    if choice != "Custom" and st.session_state.get("loaded_example") != choice:
        st.session_state["command_input"], st.session_state["loaded_example"] = EXAMPLES[choice], choice
    command = st.text_area("Proposed command", key="command_input", placeholder="kubectl get pods -n production", height=110)
    first, second = st.columns(2)
    environment = first.text_input("Target environment", key="environment_input", placeholder="production")
    resource = second.text_input("Exact resource name", key="resource_input", placeholder="api-deployment")
    if st.button("Evaluate command", type="primary", use_container_width=True):
        with st.spinner("Applying deterministic safety policy…"):
            _evaluate(command, environment, resource, client)
    evaluation: Evaluation | None = st.session_state.get("evaluation")
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
        st.metric("Deterministic policy", evaluation.decision.value)
        st.caption(st.session_state.get("model_detail", "Not evaluated."))
        st.caption("Model signals never override deterministic policy.")
    st.code(evaluation.normalized_command or evaluation.command, language="bash")
    if not context_matches:
        return
    if evaluation.decision is Decision.BLOCK:
        st.error("Blocked commands cannot be approved or simulated.")
    elif evaluation.decision is Decision.SAFE:
        if st.button("Record safe simulation"):
            result = simulate(evaluation, environment=environment, resource_name=resource)
            AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="not-required", simulation_result=result.message, environment=environment, resource_name=resource)
            st.success(result.message)
    else:
        st.subheader("Human approval required")
        confirmation = st.text_input("Type the exact resource name to approve this simulation", key="resource_confirmation")
        if st.button("Approve and record simulation"):
            try:
                approval = approve(evaluation, environment, resource, confirmation)
                result = simulate(evaluation, approval, environment=environment, resource_name=resource)
                AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="approved", confirmation_outcome="matched", simulation_result=result.message, environment=environment, resource_name=resource)
                st.success(result.message)
            except ValueError as exc:
                AUDIT.record(evaluation, decider_available=st.session_state["decider_available"], approval_outcome="denied", confirmation_outcome="not-matched", environment=environment, resource_name=resource)
                st.error(str(exc))


def policy_details() -> None:
    _header("Policy and decision details", "Rules are derived from the local deterministic evaluator; optional model output is not policy.")
    query = st.text_input("Filter policy rules", placeholder="Search identifiers, levels, or descriptions")
    rows = [{"Rule": rule, "Policy": description, "Decision": level, "Coverage": coverage} for rule, description, level, coverage in POLICY_RULES]
    if query:
        rows = [row for row in rows if query.lower() in " ".join(map(str, row.values())).lower()]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    st.info("Optional Decider output is untrusted and cannot downgrade BLOCK or authorize an action.")


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
    st.dataframe(frame, use_container_width=True, hide_index=True)
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
        {"Capability": "Command execution", "Status": "Disabled", "Detail": "No shell or infrastructure adapter exists"},
    ]), use_container_width=True, hide_index=True)
    st.subheader("Prototype limitations")
    st.markdown("- SQLite audit logs are local and not tamper-evident.\n- Approval is not identity verification or production authorization.\n- Do not submit credentials, secrets, or tokens.\n- The local Decider is optional; offline behavior uses deterministic policy.")


def main() -> None:
    _configure(); client = DeciderClient()
    with st.sidebar:
        st.markdown("## OpsGuard"); st.caption("Command safety control plane")
        page = st.radio("Navigation", ["Security Overview", "Command Playground", "Policy Details", "Audit Explorer", "System Status"])
        st.divider(); st.caption("Simulation-only prototype")
    {"Security Overview": lambda: overview(client), "Command Playground": lambda: playground(client), "Policy Details": policy_details, "Audit Explorer": audit_explorer, "System Status": lambda: system_status(client)}[page]()


if __name__ == "__main__":
    main()
