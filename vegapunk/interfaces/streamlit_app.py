"""
Streamlit UI — quick chat interface + alert dashboard.

Run: streamlit run vegapunk/interfaces/streamlit_app.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import streamlit as st

# ── Bootstrap ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Vegapunk SIEM Analyst",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def get_orchestrator():
    from vegapunk.agents.orchestrator import AgentOrchestrator
    from vegapunk.storage.manager import StorageManager
    storage = StorageManager()
    return AgentOrchestrator(storage), storage


orchestrator, storage = get_orchestrator()

# ── Sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ Vegapunk")
    st.caption("AI-powered SIEM Analyst")
    st.divider()

    page = st.radio("Navigation", ["💬 Chat", "📊 Dashboard", "📥 Ingest"])

    st.divider()
    stats = storage.stats()
    st.metric("Vector documents", stats["vector_documents"])
    for sev, cnt in stats.get("events_by_severity", {}).items():
        st.metric(f"{sev.title()} events", cnt)

    if st.button("Clear chat memory"):
        orchestrator.clear_memory()
        st.session_state.messages = []
        st.success("Memory cleared.")

# ── Chat page ────────────────────────────────────────────────────────────────

if page == "💬 Chat":
    st.header("Security Analyst Chat")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    if prompt := st.chat_input("Ask about your security logs…"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing…"):
                response = orchestrator.chat(prompt)
            st.write(response)
            st.session_state.messages.append({"role": "assistant", "content": response})

# ── Dashboard page ────────────────────────────────────────────────────────────

elif page == "📊 Dashboard":
    st.header("Alert Dashboard")

    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.selectbox(
            "Filter by severity", ["all", "critical", "high", "medium", "low"]
        )
    with col2:
        limit = st.slider("Max events", 10, 200, 50)

    sev = None if severity_filter == "all" else severity_filter
    events = storage.recent_events(limit=limit, severity=sev)

    if events:
        import pandas as pd
        df = pd.DataFrame(events)[
            ["timestamp", "severity", "host", "source_ip", "username",
             "event_category", "message"]
        ]
        sev_colors = {
            "critical": "background-color: #ff4444",
            "high": "background-color: #ff8800",
            "medium": "background-color: #ffcc00",
            "low": "background-color: #44aa44",
        }
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No events found. Ingest some logs first.")

# ── Ingest page ───────────────────────────────────────────────────────────────

elif page == "📥 Ingest":
    st.header("Ingest Log Files")

    source_type = st.selectbox("SIEM source", ["splunk", "elastic", "wazuh"])
    uploaded = st.file_uploader(
        "Upload JSON or CSV export", type=["json", "csv"], accept_multiple_files=True
    )
    run_analysis = st.checkbox("Run triage analysis after ingestion", value=True)

    if st.button("Ingest", disabled=not uploaded):
        from vegapunk.ingestion.pipeline import IngestionPipeline

        pipeline = IngestionPipeline(storage)
        total_chunks = 0

        for uf in uploaded:
            # Write to temp file
            tmp = Path(f"/tmp/{uf.name}")
            tmp.write_bytes(uf.read())

            with st.spinner(f"Ingesting {uf.name}…"):
                chunks = asyncio.run(pipeline.ingest_file(tmp, source_type))
                total_chunks += chunks

        st.success(f"Ingested {len(uploaded)} file(s) → {total_chunks} chunks.")
        st.rerun()
