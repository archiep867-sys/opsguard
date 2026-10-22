# OpsGuard

A fast safety gate for AI agents that run DevOps commands. A small decision model, **Strands
Decider 2B**, labels every command **SAFE**, **REVIEW**, or **BLOCK** with a confidence score
before anything happens. Safe commands are simulated, risky ones wait for a person who must type
the exact resource name, and dangerous ones are refused. **Amazon Bedrock** powers the agent's
conversation and plain-language explanations.

> **Safety:** OpsGuard never executes commands. There is no shell, cloud, cluster, file, or
> database adapter. "Run" always means "record a simulation".

Hackathon tags: `#strands-decider-2b` `#policy`. Reusable pattern: [docs/DECISION_PATTERN.md](docs/DECISION_PATTERN.md).

## How it decides

```
agent / user command
        │
        ▼
 ┌─────────────────┐   hard rules: destructive, shell tricks, malformed
 │ 1 POLICY CHECK  │──► BLOCK (the model is never asked)
 └────────┬────────┘
          ▼
 ┌─────────────────┐   local Strands Decider: safe / review / block + confidence
 │ 2 DECIDER VOTE  │   known commands: can only tighten the verdict
 └────────┬────────┘   unknown commands: human REVIEW at best, never SAFE
          ▼
 ┌─────────────────┐   REVIEW needs a person to type the exact resource name
 │ 3 HUMAN GATE    │   (approval is bound to one command + target, single use)
 └────────┬────────┘
          ▼
 ┌─────────────────┐
 │ 4 SIMULATION    │   records what would happen; nothing runs
 └─────────────────┘
 Bedrock (optional) explains the result in plain words. It never changes a verdict.
```

| Question | Answer |
|---|---|
| Who decides? | Deterministic rules plus the Decider. Bedrock text is never parsed for decisions. |
| Can the model make something SAFE? | No. Only the explicit read-only allowlist is SAFE. |
| Can the model unblock a command? | Only an *unknown* command, to REVIEW, when confident. Destructive commands stay blocked. |
| What if the Decider is down or confused? | Known commands keep their rule verdict; unknown commands stay blocked. |
| What does the agent do? | A Bedrock Strands agent proposes `run_command`; an `InterventionHandler` gates every call. |

## What's allowed

| Decision | What lands here |
|---|---|
| **SAFE** | Only commands on the explicit read-only allowlist (listing, describing, status, logs, `get`). |
| **REVIEW** | Changes a person must approve by typing the exact resource name: Kubernetes changes, service control, permission changes, cloud operations, file writes, and Docker, Helm and Git changes (restart, run, upgrade, commit, push, merge). |
| **BLOCK** | Destructive or dangerous commands, shell tricks, malformed input, and the AWS rules: bucket removal, recursive S3 deletes, `AdministratorAccess`, public ACLs, world-open security groups. Unknown commands are never SAFE. |

Definitions live in code: `opsguard/safety_engine.py` (decision flow and the dashboard's policy
table), `opsguard/known_commands.py` (read-only allowlist) and `opsguard/aws_rules.py` (AWS rules).

## Quick start (macOS)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt strands-decider

# Terminal 1: the local decision model (first run downloads about 4 GB)
strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8099

# Terminal 2: the dashboard
streamlit run app.py
```

Without the Decider, OpsGuard still works: known commands use the rules and unknown commands
stay blocked. The dashboard's System Status page shows what is available.

If the Decider reports `address already in use` on port 8099, it is already running. Leave it as is.

## Terminal demo (no browser needed)

```bash
python demo_agent.py      # needs the Decider server and Bedrock configured (see below)
```
A Bedrock agent proposes commands, the gate checks each one, and approvals are typed in the
terminal. Handy for recording the demo video.

## Reusable pattern

`decider_patterns/policy_gate/` is a small, app-independent copy of the pattern: a typed
`choice` question (`policy_question.py`) and a Strands `InterventionHandler` (`policy_gate.py`).
Copy it into your own agent; see [docs/DECISION_PATTERN.md](docs/DECISION_PATTERN.md).

## Amazon Bedrock (optional)

Bedrock powers (1) the **Agent Console** and (2) **Explain this decision**. It is **off by default**.

```bash
aws login                                   # or any standard AWS credential method
export AWS_REGION=us-east-1
export OPSGUARD_BEDROCK_ENABLED=true
export OPSGUARD_BEDROCK_MODEL_ID=us.amazon.nova-micro-v1:0    # an ID your account can invoke
```

* `aws login` credentials need `botocore[crt]` (already in `requirements.txt`).
* Credentials come from the standard AWS chain; nothing is stored in this repository.
* **Minimum permission** for the explanation and agent calls: `bedrock:InvokeModel` on the
  configured model (and its inference profile, if the ID starts with `us.` or `global.`).
  See [docs/iam-policy.json](docs/iam-policy.json). OpsGuard makes no other AWS calls.
* **Model access errors** (`AccessDenied`, "account is being verified") mean the account or model
  is not yet enabled for Bedrock, not that OpsGuard is broken. New accounts can take a few hours.
* **What is sent:** only sanitised decision context (command summary, verdict, rule IDs, reasons,
  Decider vote, target names). Secrets are redacted first; if redaction cannot be confirmed, no
  request is sent. Redaction is pattern-based and imperfect; do not paste secrets into OpsGuard.
* **If Bedrock is off or fails** you get a clearly labelled template explanation (never marked as
  AI), and the decision is unchanged. Statuses: `BEDROCK_DISABLED`, `BEDROCK_SUCCESS`,
  `BEDROCK_UNAVAILABLE`, `BEDROCK_INVALID`, stored in the audit log as metadata only.
* **Cost:** each explanation is one short request. Watch your AWS usage and set a budget alert.

## Audit log

Every decision is stored in SQLite (`OPSGUARD_DB_PATH`, default `./opsguard_audit.sqlite3`) with
the command (secrets redacted), matched rules, Decider vote and confidence, latency, approval
outcome, and Bedrock status. Prompts and model responses are never stored.

## Evaluate it

```bash
python eval/run_eval.py --no-decider     # rules only, offline
python eval/run_eval.py                  # needs the Decider server; writes eval/results/
```

`eval/commands.jsonl` holds 100 labelled commands (30 SAFE, 35 REVIEW, 35 BLOCK). The script
compares rules only, Decider only, and the combined pipeline, and reports accuracy, the
critical "unsafe-allow" count, over- and under-escalation, calibration by confidence, and latency.
Headline result on the 100 commands: rules 97%, Decider only 93%, combined 97%, latency about
128 ms. Full numbers (written by `eval/run_eval.py`, committed in `eval/results/`):

| mode | accuracy | unsafe-allow (BLOCK shown as SAFE) | under-escalated | over-cautious |
|---|---|---|---|---|
| rules | 97.0% | 0 | 0 | 3 |
| decider_only | 93.0% | 1 | 3 | 4 |
| combined | 97.0% | 0 | 0 | 3 |

Decider latency: median 127.7 ms, p95 137.2 ms. Rules: median 0.0193 ms.

### Read these caveats first

* **Tuned on the same set.** I tightened the AWS rules and wrote the allowlist after seeing which
  of the 100 commands failed. The 97% is **not** a held-out result and overstates performance on
  unseen commands.
* **One run on 100 commands**, so one command is one percentage point.
* **The labels are my own judgement**, not an independent review.
* **The Decider alone is not safe to rely on.** It let one BLOCK command through (item 99) and
  under-escalated three, which is why a deterministic `BLOCK` always wins.
* **Three over-cautious results are deliberate:** `cat /etc/hostname`, `terraform plan` and
  `terraform show`. An unneeded confirmation costs less than a missed one.
* **A fresh unseen set is still to do.** Until about 30 new commands are run once and reported
  separately, treat 97% as an upper bound.

Re-run the eval and re-commit `eval/results/` whenever rules or labels change.

## Tests

```bash
python -m pytest -q
```

The suite (231 tests) is fully mocked: it makes no AWS calls and needs no model. A mocked test proves the
code paths; it does not prove your AWS account works. Check that with the Agent Console or one
`aws bedrock-runtime converse` call.

## Limits

Decider 2B is experimental and small. The labelled set is small. Pattern-based redaction misses
some secrets. OpsGuard is a demonstration of a gating pattern and a simulator, not a production
control. Keep a human in the loop and least-privilege credentials on anything real.

Evaluation limits: the 97% was tuned on the same 100 commands it is scored on, from a single run,
with labels I wrote myself, so it is not a held-out measurement. The Decider alone let one BLOCK
command through and under-escalated three. See "Evaluate it" for details.

## License

MIT. See [LICENSE](LICENSE).
