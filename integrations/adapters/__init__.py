"""Adapters and factory for all configured DFIR tools."""

from integrations.adapters.amcacheparser_adapter import (
    AmcacheParserAdapter,
)
from integrations.adapters.base_adapter import BaseAdapter, ToolCommand
from integrations.adapters.evtxecmd_adapter import EvtxECmdAdapter
from integrations.adapters.hayabusa_adapter import HayabusaAdapter
from integrations.adapters.mftecmd_adapter import MFTECmdAdapter
from integrations.adapters.pecmd_adapter import PECmdAdapter
from integrations.adapters.recmd_adapter import RECmdAdapter
from integrations.parsers import create_parser
from integrations.tool_registry import ToolDefinition
from integrations.tool_runner import ToolRunner

ADAPTER_TYPES = {
    "hayabusa": HayabusaAdapter,
    "evtxecmd": EvtxECmdAdapter,
    "pecmd": PECmdAdapter,
    "amcacheparser": AmcacheParserAdapter,
    "mftecmd": MFTECmdAdapter,
    "recmd": RECmdAdapter,
}


def create_adapter(
    definition: ToolDefinition,
    runner: ToolRunner,
) -> BaseAdapter:
    try:
        adapter_type = ADAPTER_TYPES[definition.adapter]
    except KeyError as exc:
        raise ValueError(
            f"Không có adapter: {definition.adapter}"
        ) from exc
    return adapter_type(
        definition,
        runner,
        create_parser(definition.tool_id),
    )


__all__ = [
    "ADAPTER_TYPES",
    "AmcacheParserAdapter",
    "BaseAdapter",
    "EvtxECmdAdapter",
    "HayabusaAdapter",
    "MFTECmdAdapter",
    "PECmdAdapter",
    "RECmdAdapter",
    "ToolCommand",
    "create_adapter",
]
