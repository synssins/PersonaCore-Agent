"""Unit tests for tool_bridge: MCP descriptor -> OpenAI schema conversion."""

from __future__ import annotations

import pytest

from tests.fakes.fake_mcp_host import FakeMCPHost, FakeToolDescriptor
from workstation_agent.llm.tool_bridge import to_openai_schema

# ---------------------------------------------------------------------------
# to_openai_schema
# ---------------------------------------------------------------------------


class TestToOpenAISchema:
    def test_empty_list(self) -> None:
        result = to_openai_schema([])
        assert result == []

    def test_single_descriptor_shape(self) -> None:
        desc = FakeToolDescriptor(
            name="get_time",
            description="Returns the current time.",
            input_schema={"type": "object", "properties": {"tz": {"type": "string"}}},
        )
        result = to_openai_schema([desc])
        assert len(result) == 1
        tool = result[0]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "get_time"
        assert tool["function"]["description"] == "Returns the current time."
        assert tool["function"]["parameters"]["properties"]["tz"]["type"] == "string"

    def test_multiple_descriptors(self) -> None:
        descs = [
            FakeToolDescriptor("tool_a", "A"),
            FakeToolDescriptor("tool_b", "B"),
        ]
        result = to_openai_schema(descs)
        names = [r["function"]["name"] for r in result]
        assert names == ["tool_a", "tool_b"]

    def test_no_description_omits_key(self) -> None:
        desc = FakeToolDescriptor("bare_tool", description="")
        result = to_openai_schema([desc])
        assert "description" not in result[0]["function"]

    def test_default_parameters_when_missing(self) -> None:
        """Descriptor with no input_schema gets an empty object schema."""
        desc = FakeToolDescriptor("no_params")
        result = to_openai_schema([desc])
        params = result[0]["function"]["parameters"]
        assert params["type"] == "object"
        assert "properties" in params

    def test_dict_descriptor(self) -> None:
        """Accepts plain dicts in place of objects."""
        desc_dict = {
            "name": "dict_tool",
            "description": "From a dict",
            "input_schema": {"type": "object", "properties": {}},
        }
        result = to_openai_schema([desc_dict])
        assert result[0]["function"]["name"] == "dict_tool"

    def test_preserves_nested_schema(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "recursive": {"type": "boolean"},
            },
            "required": ["path"],
        }
        desc = FakeToolDescriptor("list_files", input_schema=schema)
        result = to_openai_schema([desc])
        assert result[0]["function"]["parameters"]["required"] == ["path"]

    def test_all_tools_have_type_function(self) -> None:
        descs = [FakeToolDescriptor(f"t{i}") for i in range(5)]
        for item in to_openai_schema(descs):
            assert item["type"] == "function"


# ---------------------------------------------------------------------------
# ToolRouter (basic dispatch via FakeMCPHost)
# ---------------------------------------------------------------------------


class TestToolRouter:
    @pytest.mark.asyncio
    async def test_dispatch_returns_tool_role_message(self) -> None:
        from workstation_agent.llm.client import ToolCallComplete
        from workstation_agent.llm.tool_bridge import ToolRouter

        host = FakeMCPHost(results={"echo": {"reply": "hello"}})
        router = ToolRouter(host)  # type: ignore[arg-type]

        complete = ToolCallComplete()
        complete.index = 0
        complete.call_id = "cid_1"
        complete.name = "echo"
        complete.args_json = '{"msg": "hello"}'

        msg = await router.dispatch(complete)

        assert msg["role"] == "tool"
        assert msg["tool_call_id"] == "cid_1"
        assert "reply" in msg["content"]
        assert host.calls == [("echo", {"msg": "hello"})]

    @pytest.mark.asyncio
    async def test_dispatch_invalid_json_args(self) -> None:
        from workstation_agent.llm.client import ToolCallComplete
        from workstation_agent.llm.tool_bridge import ToolRouter

        host = FakeMCPHost()
        router = ToolRouter(host)  # type: ignore[arg-type]

        complete = ToolCallComplete()
        complete.index = 0
        complete.call_id = "cid_2"
        complete.name = "any_tool"
        complete.args_json = "NOT JSON"

        msg = await router.dispatch(complete)
        assert msg["role"] == "tool"
        assert host.calls == [("any_tool", {})]

    @pytest.mark.asyncio
    async def test_dispatch_tool_error_returns_error_message(self) -> None:
        from workstation_agent.llm.client import ToolCallComplete
        from workstation_agent.llm.tool_bridge import ToolRouter

        class ErrorHost:
            async def tools(self) -> list:
                return []

            async def invoke(self, tool_id: str, args: dict) -> None:
                _ = tool_id, args
                msg = "tool exploded"
                raise RuntimeError(msg)

            async def plugins(self) -> list:
                return []

            async def reload(self, plugin_id: str) -> None:
                _ = plugin_id

        router = ToolRouter(ErrorHost())  # type: ignore[arg-type]
        complete = ToolCallComplete()
        complete.index = 0
        complete.call_id = "cid_3"
        complete.name = "bad_tool"
        complete.args_json = "{}"

        msg = await router.dispatch(complete)
        assert "error" in msg["content"]
