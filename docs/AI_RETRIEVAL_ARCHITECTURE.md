# AttackLens — AI Retrieval Architecture

> **Teaching note.** This document exists to answer one recurring question:
> *"Does AttackLens use a RAG system?"* The short answer is **no — not a
> classic vector-embedding RAG** — and the interesting part is *why that is the
> correct decision for this domain*, and what the platform uses instead. Read
> this to understand the retrieval patterns actually in the code, when each is
> appropriate, and how you would add true vector RAG **if** a use case ever
> justified it.

## Table of Contents
1. [TL;DR](#1-tldr)
2. [The Retrieval Taxonomy](#2-the-retrieval-taxonomy)
3. [Mechanism A — Structured Context-Augmentation](#3-mechanism-a--structured-context-augmentation)
4. [Mechanism B — Agentic Investigation Graph (LangGraph)](#4-mechanism-b--agentic-investigation-graph-langgraph)
5. [Grounding & Anti-Hallucination](#5-grounding--anti-hallucination)
6. [Why There Is No Vector RAG (and why that's right)](#6-why-there-is-no-vector-rag-and-why-thats-right)
7. [How to Add Real RAG to This Stack](#7-how-to-add-real-rag-to-this-stack)
8. [Deployment Summary](#8-deployment-summary)
9. [Code Reference Index](#9-code-reference-index)

---

## 1. TL;DR

AttackLens **does not** use a vector-embedding RAG system. There is no vector
store (`pgvector`, `pinecone`, `faiss`, `chromadb`, `qdrant`, `weaviate`), no
embedding model (`sentence-transformers`, `text-embedding-*`), and no
semantic/cosine similarity search anywhere in the codebase.

What it *does* have are **two retrieval-augmentation mechanisms** that are often
mistaken for RAG:

| # | Mechanism | Where |
|---|-----------|-------|
| A | **Structured context-augmentation** — keyed SQL/feed lookups injected into the prompt | `manager/manager/ai_analyst.py` |
| B | **Agentic investigation graph** — a stateful LangGraph workflow whose nodes retrieve evidence as tools | `manager/manager/ai/investigation_graph.py` |

Both are "retrieval-augmented generation" in the literal sense (the prompt is
augmented with retrieved data). Neither is a *RAG system* in the industry sense,
because retrieval is by **exact key**, not by **semantic similarity**.

---

## 2. The Retrieval Taxonomy

The word "RAG" collapses three distinct patterns. Keeping them separate is the
single most useful mental model here.

```
                       ┌─────────────────────────────────────────────┐
                       │  How does the retriever FIND the context?    │
                       └─────────────────────────────────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
 Exact KEY lookup              Graph/agent CONTROL flow         Vector SIMILARITY
 "give me CVE-2024-1234"       "the workflow decides what        "find text that
  → SQL / set membership        to fetch next, and loops"         MEANS the same"
                                                                  → embed + top-k
        │                               │                               │
   Mechanism A                     Mechanism B                    Classic RAG
   (ai_analyst.py)            (investigation_graph.py)          ❌ not in repo
```

- **Classic RAG** is for **unstructured corpora** where you *don't know the
  key* — docs, wikis, tickets, long reports. You embed the query, find the
  nearest chunks, and stuff them into the prompt.
- **Structured augmentation** is for data you can address by an **exact
  identifier** — a CVE id, an IP, a file hash, an agent id.
- **Agentic retrieval** is orthogonal to both: it is about *who decides what to
  retrieve* (a graph/agent vs. a single fixed step). AttackLens's agentic graph
  currently retrieves by exact key at each node.

---

## 3. Mechanism A — Structured Context-Augmentation

**File:** `manager/manager/ai_analyst.py` → `AIAnalyst._build_context()` and the
`_analysis_prompt()` / `_remediation_prompt()` builders.

`_build_context()` is the "retriever." Every lookup is **keyed** — there is no
similarity math:

```python
async def _build_context(self, finding: dict) -> dict:
    # KEV membership — in-memory set lookup, keyed by CVE id
    if self._feeds.is_kev_cve(cve_id):
        context["kev_match"] = True
    # Related news — SQL, keyed by CVE id
    news = await self._db.search_news_by_cve(cve_id)
    # EPSS exploit probability — keyed by CVE id
    epss_data = await self._feeds.get_epss(cve_ids[0])
    # Active threat actors — SQL query (recency-bounded)
    actors = await self._db.get_threat_actors(active_only=True, limit=5)
```

The retrieved facts are then interpolated into an f-string prompt
(`_analysis_prompt`) and sent through the provider abstraction
(`AIProvider.chat()` → `manager/manager/ai/providers.py`).

**How it is built:** an ordinary async method + prompt string. No index, no
embeddings, no background job.

**How it is deployed:** it runs inside the FastAPI manager process. Results are
cached in Postgres (the `ai_analysis` and `remediation_plans` tables) so a
finding is analysed at most once unless `force=True`. See
`manager/manager/api/remediation.py` for the HTTP surface.

---

## 4. Mechanism B — Agentic Investigation Graph (LangGraph)

**File:** `manager/manager/ai/investigation_graph.py` (~970 lines).
**Deps:** `langgraph>=1.1.0`, `langgraph-checkpoint-postgres>=3.0.0`,
`anthropic>=0.40.0`, `asyncpg`, `psycopg` (see `manager/requirements.txt`).

This is a **stateful, multi-node workflow** — the closest thing to "agentic RAG"
in the platform. State is a `TypedDict` (`InvestigationState`) carrying the
finding, frozen evidence, gathered history, intel, hypotheses, verification,
verdict, analyst decision, and remediation.

### 4.1 Graph topology

```
START
  └─► freeze_evidence      snapshot the finding's evidence (immutable for the run)
       └─► gather_history   timeline + related findings + correlations   (DB)
            └─► query_intel  per-CVE NVD/EPSS/KEV/news + per-IOC reputation (DB/feeds)
                 └─► generate_hypotheses      ← LLM
                      └─► verify_hypotheses    ← LLM (checks each against evidence)
                           └─► draft_verdict   ← LLM
                                └─► analyst_review   (human-in-the-loop gate)
                                      ├─ approve ─► draft_remediation ─► finalize_approved ─► END
                                      ├─ reject  ───────────────────────► finalize_rejected ─► END
                                      └─ expand  ─► expand_context ─┐
                                                                    └──(loops back to)─► generate_hypotheses
```

Registered in `_build_graph()` via `graph.add_node(...)` / `graph.add_edge(...)`
/ `graph.add_conditional_edges(...)`.

### 4.2 Retrieval nodes (tools, not vectors)

Each node retrieves by exact key against your existing storage — for example in
`_gather_history()` and `_query_intel()`:

```python
timeline     = await self._db.get_finding_timeline(finding_id)     # history
correlations = await self._db.get_correlations(agent_id)           # related findings
local        = await self._db.get_nvd_local_by_id(cve_id)          # CVE detail
epss         = await self._feeds.get_epss(cve_id)                  # exploit probability
is_kev       = self._feeds.is_kev_cve(cve_id)                      # active exploitation
news         = await self._db.search_news_by_cve(cve_id)           # narrative context
malicious    = self._feeds.is_malicious_ip(value)                  # IOC reputation
```

### 4.3 Durable checkpointing (the deployment story)

The graph is compiled with a **Postgres checkpointer**, so an in-flight
investigation survives a manager restart and resumes exactly where it paused
(critical for the human-in-the-loop `analyst_review` gate, which may wait hours):

```python
# investigation_graph.py :: InvestigationService.start()
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
self._checkpointer_context = AsyncPostgresSaver.from_conn_string(self._dsn)
self._checkpointer = await self._checkpointer_context.__aenter__()
await self._checkpointer.setup()
self._graph = self._build_graph().compile(checkpointer=self._checkpointer)
```

There is **no separate vector service or agent runtime**: the graph is embedded
in the manager process, and its state lives in the same PostgreSQL instance the
rest of the platform already uses. A non-Postgres DSN is rejected outright —
investigations *require* durable checkpoints.

### 4.4 Human-in-the-loop

`analyst_review` is a `add_conditional_edges` branch: the graph drafts a verdict,
then **pauses** for an analyst to `approve` / `reject` / `expand`. Approvals gate
the remediation draft; an `expand` decision loops back through
`expand_context → generate_hypotheses` for another round. High-stakes actions are
never auto-committed by the LLM alone.

---

## 5. Grounding & Anti-Hallucination

Both mechanisms use **provenance-tagged records** so the model cannot invent
sources — the same discipline a well-built vector RAG uses, applied here to
structured records:

```python
def _record(record_id: str, source: str, data: Any) -> dict:
    return {"id": record_id, "source": source, "data": _json_safe(data)}

def _citations(value: Any, allowed: set[str]) -> list[str]:
    # keep ONLY citations that reference an id we actually retrieved
    return [str(item) for item in value if str(item) in allowed][:10]
```

Every retrieved fact is wrapped by `_record()` with a stable `id`. When the LLM
emits citations, `_citations()` **drops any id that was not in the retrieved
set** — a hallucinated reference simply cannot survive. Untrusted endpoint data
is additionally shrunk and sanitised by `_json_safe()` / `_text()` (depth-capped,
`<untrusted>` tags stripped) before it ever reaches the model — see also the
`SYSTEM_PROMPT` injection defence in `manager/manager/ai/base.py`.

> Related: the `evidence_ref` contract in the validation pipeline
> (`ai_validator.py` ↔ `validation_model.py`) enforces the same
> "cite only what you were given" rule for AI-validated findings.

---

## 6. Why There Is No Vector RAG (and why that's right)

**Vector RAG is for when you don't know the key.** It earns its cost over
unstructured prose where the only way to find relevant context is *semantic
similarity*.

AttackLens's retrieval keys are **exact identifiers**: CVE ids, IPs, file
hashes, domains, agent ids. For those, an exact SQL/set lookup is:

- **More precise** — `CVE-2024-1234` returns *that* CVE's KEV/EPSS/news, never a
  "nearby" one.
- **Cheaper** — no embedding API calls on ingest or query; no index to maintain.
- **Auditable** — every fact has a row and an id (see [§5](#5-grounding--anti-hallucination)); citations are verifiable.
- **Hallucination-resistant** — there is no "fuzzy neighbour" that can smuggle in
  a wrong-but-similar record.

Introducing `pgvector` to look up a CVE by similarity would be **strictly worse**
on all four axes. The absence of RAG is therefore a deliberate, correct design
decision — not a missing feature.

**The rule to remember:** *keyed data → exact lookup; unstructured prose you must
search by meaning → vector RAG.* Almost all of AttackLens's data is the former.

---

## 7. How to Add Real RAG to This Stack

If a genuinely unstructured corpus appears — e.g. **security news articles**,
**threat-actor reports**, **past investigation narratives**, or **remediation
runbooks** — where semantic search beats keyed lookup, the cheapest path adds
**zero new infrastructure** because the platform already runs PostgreSQL.

**1. Choose the corpus** (unstructured, meaning-searched — *not* CVEs/IOCs, which
stay keyed).

**2. Deploy `pgvector` on the existing DB:**
```sql
CREATE EXTENSION IF NOT EXISTS vector;
ALTER TABLE security_news ADD COLUMN embedding vector(1024);
CREATE INDEX ON security_news USING hnsw (embedding vector_cosine_ops);
```

**3. Build the ingest side** (chunk → embed → store with a stable id):
```python
# pseudo-code — mirrors the existing feed-sync worker pattern
for doc in new_docs:
    for chunk in chunk_text(doc.body, target_tokens=400):
        vec = await embed(chunk)                 # Voyage / OpenAI embeddings API
        await db.insert_news_chunk(
            record_id=f"news:{doc.id}:{chunk.idx}",
            text=chunk.text, embedding=vec,
        )
```

**4. Retrieve by similarity, keep provenance:**
```python
qvec = await embed(query)
rows = await db.fetch(
    "SELECT record_id, text FROM security_news "
    "ORDER BY embedding <=> $1 LIMIT $2", qvec, k,
)
# feed rows into the prompt WITH their record_id, then reuse _citations()
```

**5. Slot it into the graph** as a new node — `query_semantic_context` — running
alongside `query_intel`, so **structured *and* semantic** retrieval feed the same
`generate_hypotheses` step. Reuse `_record()` / `_citations()` unchanged so the
new path inherits the anti-hallucination guard.

**When it is worth it:** only when analysts are asking meaning-based questions
("has anything *like* this been seen before?") over free text. For identifier
lookups, keep the exact path.

---

## 8. Deployment Summary

| Concern | AttackLens today |
|---|---|
| Vector store | **None** |
| Embedding model | **None** |
| Retrieval | Exact-key SQL + threat-feed set/dict lookups |
| Orchestration | LangGraph `StateGraph`, embedded in the manager process |
| Durable state | `AsyncPostgresSaver` → same PostgreSQL instance (`INTEL_DATABASE_URL`) |
| LLM transport | Provider abstraction (`ai/base.py`, `ai/providers.py`); Anthropic SDK in `ai_analyst.py` |
| Result caching | Postgres (`ai_analysis`, `remediation_plans`, `investigation_runs`) |
| Human-in-the-loop | `analyst_review` conditional edge in the graph |
| Extra services required | **None** (no vector DB, no agent runtime, no queue for AI) |

---

## 9. Code Reference Index

| What | File |
|---|---|
| Structured context-augmentation | `manager/manager/ai_analyst.py` (`_build_context`, `_analysis_prompt`, `_remediation_prompt`) |
| Remediation/analysis HTTP API | `manager/manager/api/remediation.py` |
| Provider abstraction + system prompt / injection defence | `manager/manager/ai/base.py`, `manager/manager/ai/providers.py` |
| Agentic investigation graph | `manager/manager/ai/investigation_graph.py` |
| Graph state | `investigation_graph.py :: InvestigationState` |
| Graph topology | `investigation_graph.py :: _build_graph()` |
| Retrieval nodes | `_gather_history`, `_query_intel`, `_expand_context` |
| Durable checkpoints | `InvestigationService.start()` (`AsyncPostgresSaver`) |
| Grounding / citations | `_record()`, `_citations()`, `_json_safe()`, `_text()` |
| AI/LLM dependencies | `manager/requirements.txt` |
