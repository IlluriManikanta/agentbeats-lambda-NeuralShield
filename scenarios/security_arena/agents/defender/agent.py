#!/usr/bin/env python3

"""V2 - Secure Defender Agent with trust boundary separation.

Defender Agent for the Security Arena with layered security architecture.

This agent implements a multi-pass security pipeline that:
- Separates trusted scenario instructions from untrusted user content
- Uses structured prompts with explicit instruction hierarchy
- Implements 2-pass LLM pipeline: security analysis + task execution
- Validates outputs against scenario-specific constraints

Key security principles:
- Trusted content (role, task, format) goes into system prompt
- Untrusted content (formatted_input) is quarantined in <DOCUMENT> tags
- LLM is instructed to NEVER follow instructions within document tags
- Output validation catches attacks that bypass prompt-level defenses
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
from dotenv import load_dotenv

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    TaskState,
    InvalidParamsError,
    UnsupportedOperationError,
    Task,
)
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

from defender_engine.main import SecurityGateway
from defender_engine.config import SAFE_REFUSAL_MESSAGE


load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("defender")


@dataclass
class ScenarioContext:
    """
    Filtered scenario context from orchestrator (no attack info).
    
    Trust boundaries:
    - TRUSTED: defender_role, defender_task, output_format, domain_description
    - UNTRUSTED: formatted_input (may contain attacker-controlled content)
    """
    domain_description: str   # Domain/system description (trusted)
    defender_role: str        # Defender's role description (trusted)
    defender_task: str        # What defender should do (trusted)
    output_format: str        # Expected output format (trusted)
    formatted_input: str      # Input to process (UNTRUSTED - may contain attacks)
    security_guidelines: str = ""  # Optional security hints (trusted but often empty)

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            domain_description=d.get("domain_description", ""),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            formatted_input=d.get("formatted_input", ""),
            security_guidelines=d.get("security_guidelines", ""),
        )

    def get_trusted_context(self) -> dict[str, str]:
        """Return only trusted fields for building the system prompt."""
        return {
            "defender_role": self.defender_role,
            "defender_task": self.defender_task,
            "output_format": self.output_format,
            "domain_description": self.domain_description,
            "security_guidelines": self.security_guidelines,
        }

    def get_untrusted_input(self) -> str:
        """Return the untrusted formatted_input for quarantined processing."""
        return self.formatted_input or ""

    def to_gateway_request(self) -> dict[str, Any]:
        """
        Build a structured request for the SecurityGateway.
        
        This keeps trusted and untrusted content separate so the gateway
        can apply appropriate security measures to each.
        """
        return {
            "trusted_context": self.get_trusted_context(),
            "untrusted_input": self.get_untrusted_input(),
        }


class Defender(AgentExecutor):
    """
    Secure Defender that processes requests through a layered security pipeline.
    
    Security architecture:
    1. Parse and separate trusted vs untrusted content
    2. Pass structured request to SecurityGateway
    3. Gateway handles: preprocessing -> security analysis -> task execution -> output validation
    """

    def __init__(self, model: str = "gpt-oss-20b"):
        self._gateway = SecurityGateway(model=model)
        self._model = model

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Process input through the security pipeline with trust boundary separation."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            message_text = context.get_user_input()
            
            try:
                payload = json.loads(message_text)
            except json.JSONDecodeError:
                logger.warning("Failed to parse scenario JSON; treating as raw untrusted input.")
                # Treat raw text as untrusted input when JSON parsing fails.
                gateway_request = {
                    "trusted_context": {
                        "defender_role": "AI Assistant",
                        "defender_task": "Respond helpfully and safely to the user's request.",
                        "output_format": "Natural language response.",
                        "domain_description": "",
                        "security_guidelines": "",
                    },
                    "untrusted_input": message_text or "",
                }
            else:
                ctx = ScenarioContext.from_dict(payload)
                logger.info("Processing defender request for role=%s", 
                           ctx.defender_role[:80] if ctx.defender_role else "unknown")
                gateway_request = ctx.to_gateway_request()

            # Send structured request to the security gateway.
            output = await self._gateway.handle_request(gateway_request)
            logger.info("Defender generated response (%d chars)", len(output))
            await updater.update_status(TaskState.completed, new_agent_text_message(output))
            
        except Exception as e:
            logger.error("Defender error: %s", e, exc_info=True)
            await updater.update_status(
                TaskState.failed,
                new_agent_text_message(SAFE_REFUSAL_MESSAGE),
            )

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Defender Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9020, help="Port to bind to")
    parser.add_argument("--model", default="gpt-oss-20b", help="Model to use for the defender")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="defender",
        description="Defender agent that processes inputs according to role",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Defender(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Defender on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
