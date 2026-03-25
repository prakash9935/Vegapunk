"""
Agent Orchestrator — LangGraph-powered.

Two graphs:

1. AnalysisGraph (StateGraph)
   START → triage (Haiku) → [conditional] → analyst (Sonnet) → store → END
                                          ↘ store → END  (if no escalation)

2. ChatAgent (LangGraph prebuilt ReAct)
   Haiku/Sonnet with tools: vector_search, sql_query, mitre_lookup
   MemorySaver provides automatic sliding-window conversation state.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import StructuredTool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field

from vegapunk.agents.analyst import AnalystAgent
from vegapunk.agents.triage import TriageAgent
from vegapunk.config import settings
from vegapunk.models import AnalysisResult, NormEvent, TriageResult
from vegapunk.prompts.analysis import CHAT_SYSTEM
from vegapunk.storage.manager import StorageManager

logger = logging.getLogger(__name__)


# ── Graph state ──────────────────────────────────────────────────────────────

class AnalysisState(TypedDict):
    event: NormEvent
    triage: TriageResult | None
    analysis: AnalysisResult | None


# ── Tool input schemas (required by StructuredTool) ──────────────────────────

class VectorSearchInput(BaseModel):
    query: str = Field(description="Natural language search query")

class SQLQueryInput(BaseModel):
    query: str = Field(description="SQL SELECT statement")

class MITREInput(BaseModel):
    ids: str = Field(description="Comma-separated ATT&CK IDs e.g. 'TA0006,T1110'")


# ── Tool factories ────────────────────────────────────────────────────────────

def _make_tools(storage: StorageManager) -> list[StructuredTool]:
    """Build LangGraph-compatible tools bound to the storage manager."""

    def vector_search(query: str) -> str:
        results = storage.semantic_search(query, n=8)
        if not results:
            return "No similar events found."
        lines = []
        for i, r in enumerate(results, 1):
            meta = r["metadata"]
            ts = meta.get("timestamp", meta.get("window_start", "?"))
            src = meta.get("source_type", "?")
            lines.append(f"[{i}] {ts} ({src})\n{r['document'][:300]}")
        return "\n\n".join(lines)

    def sql_query(query: str) -> str:
        import json
        q = query.strip()
        if not q.lower().startswith("select"):
            return "Error: only SELECT statements are allowed."
        rows = storage.sql_query(q)
        return json.dumps(rows[:50], indent=2, default=str) if rows else "No results."

    def mitre_lookup(ids: str) -> str:
        from vegapunk.agents.tools.mitre import _TACTICS, _TECHNIQUES
        results = []
        for id_ in [i.strip().upper() for i in ids.split(",")]:
            if id_ in _TACTICS:
                results.append(f"{id_} [Tactic]: {_TACTICS[id_]}")
            elif id_ in _TECHNIQUES:
                results.append(f"{id_} [Technique]: {_TECHNIQUES[id_]}")
            else:
                results.append(f"{id_}: Not found in local ATT&CK index.")
        return "\n".join(results)

    return [
        StructuredTool.from_function(
            func=vector_search,
            name="vector_search",
            description=(
                "Semantic similarity search over ingested SIEM logs. "
                "Use to find events related to a threat, IP, user, or behaviour."
            ),
            args_schema=VectorSearchInput,
        ),
        StructuredTool.from_function(
            func=sql_query,
            name="sql_query",
            description=(
                "Read-only SQL SELECT against the SIEM metadata database. "
                "Tables: events, chunks, triage_results, analysis_results. "
                "events columns: id, timestamp, message, host, source_ip, "
                "dest_ip, username, process, event_category, event_action, severity."
            ),
            args_schema=SQLQueryInput,
        ),
        StructuredTool.from_function(
            func=mitre_lookup,
            name="mitre_lookup",
            description="Look up MITRE ATT&CK tactic/technique IDs for descriptions.",
            args_schema=MITREInput,
        ),
    ]


# ── Analysis graph ────────────────────────────────────────────────────────────

def _build_analysis_graph(
    triage_agent: TriageAgent,
    analyst_agent: AnalystAgent,
    storage: StorageManager,
) -> Any:
    """
    StateGraph: triage → [conditional] → analyst → store → END
                                       ↘ store → END
    """

    async def triage_node(state: AnalysisState) -> AnalysisState:
        result = triage_agent.triage(state["event"])
        await storage.store_triage(result)
        logger.info(
            "Triage: event=%s severity=%s confidence=%.0f%% escalate=%s",
            state["event"].id[:8], result.severity.value,
            result.confidence * 100, result.needs_deep_analysis,
        )
        return {**state, "triage": result}

    async def analyst_node(state: AnalysisState) -> AnalysisState:
        result = analyst_agent.analyze(state["event"], state["triage"])
        await storage.store_analysis(result)
        logger.info("Analysis complete: event=%s", state["event"].id[:8])
        return {**state, "analysis": result}

    def route(state: AnalysisState) -> Literal["analyst", "end"]:
        return "analyst" if state["triage"].needs_deep_analysis else "end"

    graph = StateGraph(AnalysisState)
    graph.add_node("triage", triage_node)
    graph.add_node("analyst", analyst_node)

    graph.add_edge(START, "triage")
    graph.add_conditional_edges("triage", route, {"analyst": "analyst", "end": END})
    graph.add_edge("analyst", END)

    return graph.compile()


# ── Orchestrator ──────────────────────────────────────────────────────────────

class AgentOrchestrator:
    """
    Central coordinator using two LangGraph graphs.

    Event flow  → AnalysisGraph (triage → optional analyst → store)
    Chat flow   → ChatAgent (ReAct with vector/SQL/MITRE tools + memory)
    """

    def __init__(self, storage: StorageManager) -> None:
        self._storage = storage
        self._triage = TriageAgent(storage)
        self._analyst = AnalystAgent(storage)

        # Analysis graph (event processing)
        self._analysis_graph = _build_analysis_graph(
            self._triage, self._analyst, storage
        )

        # Chat agent (ReAct + persistent memory per thread)
        self._chat_memory = MemorySaver()
        self._chat_model = ChatAnthropic(
            model=settings.analyst_model,
            api_key=settings.anthropic_api_key,
            max_tokens=2048,
        )
        self._chat_agent = create_react_agent(
            model=self._chat_model,
            tools=_make_tools(storage),
            prompt=CHAT_SYSTEM,
            checkpointer=self._chat_memory,
        )
        # Single thread id for the CLI/Streamlit session
        self._thread_id = "default"

    # ── Event analysis ────────────────────────────────────────────────────────

    async def process_event(
        self, event: NormEvent
    ) -> tuple[TriageResult, AnalysisResult | None]:
        """Run the analysis graph for a single event."""
        initial: AnalysisState = {"event": event, "triage": None, "analysis": None}
        final = await self._analysis_graph.ainvoke(initial)
        return final["triage"], final.get("analysis")

    async def process_events(
        self, events: list[NormEvent]
    ) -> list[tuple[TriageResult, AnalysisResult | None]]:
        """Batch process events through the analysis graph."""
        import asyncio
        return list(await asyncio.gather(*[self.process_event(e) for e in events]))

    # ── Chat ──────────────────────────────────────────────────────────────────

    def chat(self, user_message: str, thread_id: str | None = None) -> str:
        """
        Answer a security question using the ReAct chat agent.
        LangGraph MemorySaver handles conversation history automatically.
        Pass different thread_id values to maintain separate sessions
        (e.g. one per Slack user, one per Streamlit session).
        """
        config = {"configurable": {"thread_id": thread_id or self._thread_id}}
        result = self._chat_agent.invoke(
            {"messages": [{"role": "user", "content": user_message}]},
            config=config,
        )
        messages = result.get("messages", [])
        return messages[-1].content if messages else "No response generated."

    def clear_memory(self, thread_id: str | None = None) -> None:
        """Reset conversation memory for a thread."""
        # MemorySaver doesn't expose a delete API — create a fresh checkpointer
        self._chat_memory = MemorySaver()
        self._chat_agent = create_react_agent(
            model=self._chat_model,
            tools=_make_tools(self._storage),
            prompt=CHAT_SYSTEM,
            checkpointer=self._chat_memory,
        )

    def stats(self) -> dict[str, Any]:
        return {"storage": self._storage.stats()}
