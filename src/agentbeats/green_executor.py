from abc import abstractmethod
import os
from pydantic import ValidationError

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import (
    InvalidParamsError,
    Task,
    TaskState,
    UnsupportedOperationError,
    InternalError,
)
from a2a.utils import (
    new_agent_text_message,
    new_task,
)
from a2a.utils.errors import ServerError

from agentbeats.models import EvalRequest
from agentbeats.debug_runtime import append_debug_log


class GreenAgent:

    @abstractmethod
    async def run_eval(self, request: EvalRequest, updater: TaskUpdater) -> None:
        pass

    @abstractmethod
    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        pass


class GreenExecutor(AgentExecutor):

    def __init__(self, green_agent: GreenAgent):
        self.agent = green_agent

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        run_id = os.getenv("AGENTBEATS_DEBUG_RUN_ID", "pre-fix")
        request_text = context.get_user_input()
        try:
            req: EvalRequest = EvalRequest.model_validate_json(request_text)
            ok, msg = self.agent.validate_request(req)
            if not ok:
                raise ServerError(error=InvalidParamsError(message=msg))
        except ValidationError as e:
            raise ServerError(error=InvalidParamsError(message=e.json()))

        msg = context.message
        if msg:
            task = new_task(msg)
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H4",
                location="src/agentbeats/green_executor.py:execute:task_created",
                message="Server received eval request",
                data={
                    "task_id": task.id,
                    "context_id": task.context_id,
                    "request_chars": len(request_text or ""),
                },
            )
            # endregion
            await event_queue.enqueue_event(task)
        else:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        updater = TaskUpdater(event_queue, task.id, task.context_id)
        await updater.update_status(
            TaskState.working,
            new_agent_text_message(f"Starting assessment.\n{req.model_dump_json()}", context_id=context.context_id)
        )

        try:
            await self.agent.run_eval(req, updater)
            # Only complete if not already in terminal state (agent may have called complete/failed)
            try:
                await updater.complete()
            except RuntimeError:
                pass  # Task already completed by agent
        except Exception as e:
            print(f"Agent error: {e}")
            # region agent log
            append_debug_log(
                run_id=run_id,
                hypothesis_id="H4",
                location="src/agentbeats/green_executor.py:execute:run_eval_exception",
                message="run_eval raised exception",
                data={
                    "exception_type": type(e).__name__,
                    "exception_message": str(e),
                    "context_id": context.context_id,
                    "task_id": task.id,
                },
            )
            # endregion
            try:
                await updater.failed(new_agent_text_message(f"Agent error: {e}", context_id=context.context_id))
            except RuntimeError:
                pass  # Task already in terminal state
            raise ServerError(error=InternalError(message=str(e)))

    async def cancel(
        self, request: RequestContext, event_queue: EventQueue
    ) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())
