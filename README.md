# Vegapunk

**AI-powered SIEM analysis agent.** Ingests security logs from Wazuh Cloud or local files, triages every event with Claude Haiku, escalates high-severity findings to Claude Sonnet for deep analysis, and lets you query your entire alert history through a natural-language chat interface.


## Requirements

- Python 3.11+
- [Anthropic API key](https://console.anthropic.com/)
- Wazuh Cloud account *(optional — only needed for `watch` / `export`)*

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/yourname/vegapunk.git
cd vegapunk

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .
```

### 2. Configure environment

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum:

```env
ANTHROPIC_API_KEY=sk-ant-...

# Only required for vegapunk watch / vegapunk export
WAZUH_CLOUD_URL=https://my-env.wazuh.cloud
WAZUH_USERNAME=admin
WAZUH_PASSWORD=...
```

### 3. Ingest your first file

Vegapunk ships with a Wazuh sample. Point it at any exported alert file:

```bash
vegapunk ingest data/samples/wzuh_sample.json --source wazuh
```


### 4. Chat with your data

```bash
vegapunk chat
```

```
You: Show me all critical alerts from the last 24 hours
You: What MITRE techniques are associated with the SSH brute-force events?
You: Summarise lateral movement activity
```

Type `clear` to reset conversation memory, `exit` to quit.

---

## All Commands

| Command | Description |
|---|---|
| `vegapunk ingest <file> --source <src>` | Parse and store a local SIEM export |
| `vegapunk analyze <file> --source <src>` | Ingest + run triage/analysis on every event |
| `vegapunk watch [--interval N]` | Live-poll Wazuh Cloud and continuously ingest |
| `vegapunk export [--hours N] [--output <file>]` | Dump Wazuh Cloud alerts to a local JSON file |
| `vegapunk chat` | Interactive natural-language query REPL |
| `vegapunk stats` | Show storage statistics |

### `vegapunk watch`

Continuously polls Wazuh Cloud every N seconds, normalises and stores each batch, then runs triage+analysis automatically:

```bash
vegapunk watch --interval 30
vegapunk watch --no-analyze          # store only, skip triage
```

Critical events are printed in real time. Press `Ctrl+C` to stop.

### `vegapunk export`

Downloads alerts in bulk without keeping a long-running process. Useful for offline analysis or one-off ingestion:

```bash
vegapunk export --hours 48 --output alerts_yesterday.json
vegapunk ingest alerts_yesterday.json --source wazuh
```

### `vegapunk analyze`

Ingest a file and immediately run triage+analysis, printing a results table:

```bash
vegapunk analyze wazuh_alerts_20260324.json --source wazuh
```

---

## Configuration Reference

All settings are read from `.env` (or environment variables).

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | *(required)* | Anthropic API key |
| `WAZUH_CLOUD_URL` | — | Wazuh Cloud base URL |
| `WAZUH_USERNAME` | `admin` | Wazuh / OpenSearch username |
| `WAZUH_PASSWORD` | — | Wazuh / OpenSearch password |
| `WAZUH_POLL_INTERVAL` | `60` | Seconds between polls in `watch` mode |
| `TRIAGE_MODEL` | `claude-haiku-4-5-20251001` | Model used for fast triage |
| `ANALYST_MODEL` | `claude-sonnet-4-6` | Model used for deep analysis |
| `TRIAGE_CONFIDENCE_THRESHOLD` | `0.75` | Escalate to analyst if below this |
| `CHUNK_WINDOW_MINUTES` | `15` | Time-window size per log chunk |
| `MAX_CHUNK_EVENTS` | `100` | Max events per chunk |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |


## License

MIT
