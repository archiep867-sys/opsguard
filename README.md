<div align="center">

# ConstructMind AI

**An AI employee for construction procurement and supply chain — built for the Build with Gemini XPRIZE Hackathon 2026.**

[Live Demo](<Live Demo URL>) · [Demo Video](<Demo Video URL>) · [Devpost Submission](<Devpost Submission URL>)

</div>

---

## Overview

Construction project managers lose 6–10 hours a week reconstructing information that already exists — scattered across emails, PDFs, purchase orders, invoices, spreadsheets, ERP exports, and WhatsApp threads. ConstructMind AI reads all of it, understands it, and reasons about it, so a question like *"Will Building A finish on time?"* gets one explainable, cited answer instead of an afternoon of digging.

It isn't a chatbot bolted onto a document store. ConstructMind AI runs a team of specialized AI agents — Planning, Procurement, Supply Chain, and Risk — that each analyze their domain and synthesize into a single, source-cited answer, backed by a Retrieval-Augmented Generation pipeline over every document a project produces.

Built entirely on Google's Gemini models for the Build with Gemini XPRIZE Hackathon.

## Features

- **Document Intelligence** — upload POs, invoices, contracts, BOQs, BOMs, drawings, delivery receipts, and quotations; Gemini classifies, extracts structured fields, and indexes everything automatically
- **Multimodal understanding** — scanned drawings and site photos are read directly with Gemini's vision capabilities, not just OCR'd as flat text
- **RAG-powered chat** — ask natural-language questions across every project document; every answer cites its source
- **Multi-agent reasoning** — Planning, Procurement, Supply Chain, and Risk agents collaborate on complex questions and return one explainable answer with a visible reasoning trace
- **Proactive risk alerts** — delayed deliveries, duplicate invoices, price anomalies, and inventory shortfalls are surfaced automatically with a confidence score and plain-language reasoning
- **Vendor intelligence** — suppliers are scored on delivery reliability, price consistency, and responsiveness
- **Workflow automation (human-in-the-loop)** — AI drafts purchase orders, vendor comparison reports, and executive summaries for one-click human approval — nothing sends automatically
- **Role-based dashboards** — Admin, Project Manager, and Procurement Manager each get a purpose-built view

## Architecture

```
Next.js Frontend  →  FastAPI Backend  →  Agent Orchestrator (Gemini)
                                       →  Document Pipeline (extract/classify/embed)
                                       →  Supabase Postgres (structured data, RLS)
                                       →  pgvector (embeddings, RAG retrieval)
                                       →  Supabase Storage (original files)
```

Documents are processed once into structured fields and embeddings; every agent reads from that same store, which is what lets four agents "collaborate" on one answer without re-parsing raw files or blowing the latency budget. See [`/docs/architecture.md`](./architecture.md) for the full system, sequence, and ER diagrams.

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Frontend | Next.js 15 (App Router), TypeScript, Tailwind CSS, shadcn/ui | Server components for data-heavy dashboards; full control over a premium, non-templated UI |
| Backend | FastAPI (Python) | Async-native, and the same language as the AI/agent pipeline |
| Database | Supabase (Postgres + pgvector + Auth + Storage + Row-Level Security) | One provider for relational data, vector search, auth, and files — real multi-tenant isolation at the database layer |
| AI Models | Gemini 2.5 Pro / Flash (Vertex AI / Gemini API) | Multimodal reasoning over documents, drawings, and photos; required by the hackathon track |
| Embeddings | Gemini text-embedding-004 | One AI provider across the whole surface — simpler credentials and latency profile |
| Deployment | Vercel (frontend) + Google Cloud Run (backend) | Cloud Run keeps latency low to Vertex AI and stays fully within the Google stack |
| Testing | Vitest, Playwright (frontend) · Pytest (backend) | Standard, fast, CI-friendly |

## Installation

```bash
# 1. Clone the repository
git clone <GitHub Repository URL>
cd constructmind-ai

# 2. Install frontend dependencies
cd apps/web
npm install

# 3. Install backend dependencies
cd ../api
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Fill in: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,
#          GEMINI_API_KEY, GOOGLE_CLOUD_PROJECT

# 5. Run database migrations
cd infra/supabase
supabase db push

# 6. Start the backend
cd apps/api
uvicorn app.main:app --reload

# 7. Start the frontend
cd apps/web
npm run dev
```

The app will be available at `http://localhost:3000`, with the API at `http://localhost:8000`.

## Folder Structure

```
constructmind-ai/
├── apps/
│   ├── web/                  # Next.js frontend
│   │   ├── app/               # App Router pages (dashboard, chat, procurement, vendors...)
│   │   ├── components/        # UI primitives, charts, agent-chat, dashboard widgets
│   │   └── lib/                # API client, auth helpers
│   └── api/                   # FastAPI backend
│       ├── app/api/v1/         # REST routers (auth, documents, projects, chat, alerts...)
│       ├── app/agents/         # Planning, Procurement, Supply Chain, Risk agents + orchestrator
│       ├── app/pipeline/       # Extraction, classification, embedding
│       ├── app/db/             # Models, session
│       └── app/tests/
├── packages/shared-types/     # Shared TS types generated from the API schema
├── infra/
│   ├── supabase/               # Migrations, RLS policies
│   └── docker/
└── docs/                        # This README, architecture diagrams, product plan
```

## AI Workflow

1. **Ingest** — a document is uploaded and stored; a background job extracts raw text (Gemini multimodal for scans/drawings, direct parsing for text-native files)
2. **Classify & extract** — Gemini classifies the document type and pulls structured fields (vendor, amounts, dates, quantities, clauses) into Postgres
3. **Embed** — the document is chunked and embedded (Gemini embeddings) into pgvector for retrieval
4. **Query** — a user question is embedded and matched against relevant chunks, scoped to their organization and project
5. **Orchestrate** — the orchestrator routes the question to the relevant agent(s); each agent reasons over its domain and returns findings, a confidence score, and sources
6. **Synthesize** — the orchestrator combines agent outputs into one explainable answer with an inline reasoning trace and citations back to source documents
7. **Act (with approval)** — for workflow requests, the relevant agent drafts the artifact (PO, report, summary) and a human approves before anything is finalized

## Future Scope

- Vendor Intelligence, Scheduling, Document Intelligence, and Workflow Automation as standalone agents (interfaces already defined)
- Trained ML forecasting models once sufficient historical project data exists, alongside the current LLM-reasoning-based predictions
- ERP integrations (Procore, SAP Ariba, Autodesk Construction Cloud)
- A scoped vendor portal with its own authentication and row-level isolation
- Native mobile app for site engineers

## License

MIT License — see [`LICENSE`](./LICENSE).

## Contributors

Built by the ConstructMind AI team for the Build with Gemini XPRIZE Hackathon 2026.

| Name | Role |
|---|---|
| <Contributor Name> | <Role> |
| <Contributor Name> | <Role> |
| <Contributor Name> | <Role> |
