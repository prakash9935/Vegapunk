"""
Slack bot — alert-triggered and interactive queries.

Uses Slack Bolt with socket mode for zero-infrastructure setup.
Set SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET in .env.

Usage:
  python -m vegapunk.interfaces.slack_bot
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def start_slack_bot() -> None:
    """Start the Slack bot. Raises if tokens are not configured."""
    from vegapunk.config import settings

    if not settings.slack_bot_token or not settings.slack_signing_secret:
        raise RuntimeError(
            "SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET must be set in .env"
        )

    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler

    from vegapunk.agents.orchestrator import AgentOrchestrator
    from vegapunk.storage.manager import StorageManager

    storage = StorageManager()
    orchestrator = AgentOrchestrator(storage)
    app = App(token=settings.slack_bot_token)

    @app.event("app_mention")
    def handle_mention(event, say, client):
        """Respond to @vegapunk mentions."""
        text = event.get("text", "").strip()
        # Strip the mention prefix (<@BOTID> ...)
        if ">" in text:
            text = text.split(">", 1)[1].strip()

        if not text:
            say("Hi! Ask me anything about your SIEM logs.")
            return

        say(f"Analyzing: _{text}_")
        try:
            response = orchestrator.chat(text)
            # Split long responses across multiple blocks
            blocks = [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": chunk},
                }
                for chunk in _split(response, 2900)
            ]
            client.chat_postMessage(
                channel=event["channel"],
                blocks=blocks,
                text=response[:200],
            )
        except Exception as exc:
            logger.error("Slack handler error: %s", exc)
            say(f"Error: {exc}")

    @app.message("help")
    def handle_help(message, say):
        say(
            "*Vegapunk SIEM Analyst*\n"
            "• Mention me with a question: `@vegapunk show me failed logins in the last hour`\n"
            "• I can search logs, correlate events, and map to MITRE ATT&CK\n"
        )

    logger.info("Starting Vegapunk Slack bot…")
    SocketModeHandler(app, settings.slack_signing_secret).start()


def _split(text: str, chunk_size: int) -> list[str]:
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    start_slack_bot()
