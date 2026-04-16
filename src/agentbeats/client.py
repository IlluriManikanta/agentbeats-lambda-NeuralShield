import asyncio
import os
from uuid import uuid4

import httpx
from a2a.client import (
    A2ACardResolver,
    ClientConfig,
    ClientFactory,
    Consumer,
)
from agentbeats.debug_runtime import append_debug_log
from a2a.types import (
    Message,
    Part,
    Role,
    TextPart,
    DataPart,
)


# Overall HTTP timeout for the entire battle/evaluation
# This must be long enough to accommodate all rounds (e.g., 20 rounds × 300s per agent × 2 agents)
# Set high to avoid premature timeouts; per-agent timeouts are handled by the orchestrator
DEFAULT_TIMEOUT = 3600  # 1 hour


def create_message(*, role: Role = Role.user, text: str, context_id: str | None = None) -> Message:
    return Message(
        kind="message",
        role=role,
        parts=[Part(TextPart(kind="text", text=text))],
        message_id=uuid4().hex,
        context_id=context_id
    )

def merge_parts(parts: list[Part]) -> str:
    chunks = []
    for part in parts:
        if isinstance(part.root, TextPart):
            chunks.append(part.root.text)
        elif isinstance(part.root, DataPart):
            chunks.append(part.root.data)
    return "\n".join(chunks)

async def send_message(message: str, base_url: str, context_id: str | None = None, streaming=False, consumer: Consumer | None = None):
    """Returns dict with context_id, response and status (if exists)"""
    run_id = os.getenv("AGENTBEATS_DEBUG_RUN_ID", "pre-fix")
    # region agent log
    append_debug_log(
        run_id=run_id,
        hypothesis_id="H2",
        location="src/agentbeats/client.py:send_message:entry",
        message="Entering send_message",
        data={
            "base_url": base_url,
            "streaming": streaming,
            "has_context_id": context_id is not None,
            "http_proxy_set": bool(os.getenv("HTTP_PROXY") or os.getenv("http_proxy")),
            "https_proxy_set": bool(os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")),
            "no_proxy_set": bool(os.getenv("NO_PROXY") or os.getenv("no_proxy")),
        },
    )
    # endregion
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as httpx_client:
        try:
            resolver = A2ACardResolver(httpx_client=httpx_client, base_url=base_url)
            agent_card = await resolver.get_agent_card()
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H2",
                location="src/agentbeats/client.py:send_message:card",
                message="Resolved agent card",
                data={
                    "base_url": base_url,
                    "card_url": str(agent_card.url),
                },
            )
            # endregion

            # Override the agent card URL with the base_url we were given
            # This is necessary because agents may advertise 0.0.0.0 or localhost
            # but we need to use the actual container hostname
            agent_card.url = base_url.rstrip("/") + "/"

            config = ClientConfig(
                httpx_client=httpx_client,
                streaming=streaming,
            )
            factory = ClientFactory(config)
            client = factory.create(agent_card)
            if consumer:
                await client.add_event_consumer(consumer)

            outbound_msg = create_message(text=message, context_id=context_id)
            last_event = None
            outputs = {
                "response": "",
                "context_id": None
            }
            event_count = 0

            # if streaming == False, only one event is generated
            async for event in client.send_message(outbound_msg):
                event_count += 1
                last_event = event

            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H2",
                location="src/agentbeats/client.py:send_message:events_complete",
                message="Finished receiving events",
                data={
                    "event_count": event_count,
                    "last_event_type": type(last_event).__name__ if last_event is not None else "None",
                },
            )
            # endregion

            match last_event:
                case Message() as msg:
                    outputs["context_id"] = msg.context_id
                    outputs["response"] += merge_parts(msg.parts)

                case (task, update):
                    outputs["context_id"] = task.context_id
                    outputs["status"] = task.status.state.value
                    msg = task.status.message
                    if msg:
                        outputs["response"] += merge_parts(msg.parts)
                    if task.artifacts:
                        for artifact in task.artifacts:
                            outputs["response"] += merge_parts(artifact.parts)

                case _:
                    pass

            return outputs
        except Exception as exc:
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H2",
                location="src/agentbeats/client.py:send_message:exception",
                message="send_message raised exception",
                data={
                    "exception_type": type(exc).__name__,
                    "exception_message": str(exc),
                    "base_url": base_url,
                },
            )
            # endregion
            raise
