"""Run the official Python SDK as a real A2A v1.0 server, to point ``a2aops conformance`` at.

    pip install "a2a-sdk[http-server]==1.3.0" uvicorn      # not an a2aops dependency
    python -m bench.sdk_server 8765                         # serves JSON-RPC and HTTP+JSON on 127.0.0.1:8765
    a2aops conformance http://127.0.0.1:8765 --active

The agent is the smallest thing the SDK documents: one executor that completes a task
with a text artifact. Nothing here talks to the network except the loopback listener.
"""

from __future__ import annotations

import sys


def build_app(port: int):
    from starlette.applications import Starlette

    from a2a.helpers.proto_helpers import new_task, new_text_artifact
    from a2a.server.agent_execution import AgentExecutor
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes, create_rest_routes
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.types.a2a_pb2 import (AgentCapabilities, AgentCard, AgentInterface, AgentSkill,
                                   TaskArtifactUpdateEvent, TaskState, TaskStatus, TaskStatusUpdateEvent)

    base = f"http://127.0.0.1:{port}"
    card = AgentCard(
        name="SDK reference agent", description="Official a2a-sdk completing every task with one artifact.",
        version="1.0.0",
        supported_interfaces=[
            AgentInterface(url=base + "/rpc", protocol_binding="JSONRPC", protocol_version="1.0"),
            AgentInterface(url=base + "/rest", protocol_binding="HTTP+JSON", protocol_version="1.0")],
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        default_input_modes=["text/plain"], default_output_modes=["text/plain"],
        skills=[AgentSkill(id="echo", name="Echo", description="Echoes the request.", tags=["demo"])])

    class Echo(AgentExecutor):
        async def execute(self, context, event_queue):
            task = new_task(context.task_id, context.context_id, TaskState.TASK_STATE_SUBMITTED)
            await event_queue.enqueue_event(task)
            await event_queue.enqueue_event(TaskArtifactUpdateEvent(
                task_id=context.task_id, context_id=context.context_id,
                artifact=new_text_artifact("result", "echo: " + context.get_user_input())))
            await event_queue.enqueue_event(TaskStatusUpdateEvent(
                task_id=context.task_id, context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED)))

        async def cancel(self, context, event_queue):
            await event_queue.enqueue_event(TaskStatusUpdateEvent(
                task_id=context.task_id, context_id=context.context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_CANCELED)))

    handler = DefaultRequestHandler(agent_executor=Echo(), task_store=InMemoryTaskStore(), agent_card=card)
    routes = (create_agent_card_routes(card) + create_jsonrpc_routes(handler, "/rpc")
              + create_rest_routes(handler, path_prefix="/rest"))
    return Starlette(routes=routes)


if __name__ == "__main__":
    import uvicorn
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    uvicorn.run(build_app(port), host="127.0.0.1", port=port, log_level="warning")
