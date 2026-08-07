"""Parser implementations for supported external DFIR tools."""

from integrations.parsers.amcacheparser_parser import AmcacheParserParser
from integrations.parsers.base_parser import BaseParser, RowView
from integrations.parsers.evtxecmd_parser import EvtxECmdParser
from integrations.parsers.hayabusa_parser import HayabusaParser
from integrations.parsers.mftecmd_parser import MFTECmdParser
from integrations.parsers.pecmd_parser import PECmdParser
from integrations.parsers.recmd_parser import RECmdParser

PARSER_TYPES = {
    "hayabusa": HayabusaParser,
    "evtxecmd": EvtxECmdParser,
    "pecmd": PECmdParser,
    "amcacheparser": AmcacheParserParser,
    "mftecmd": MFTECmdParser,
    "recmd": RECmdParser,
}


def create_parser(tool_id: str) -> BaseParser:
    try:
        parser_type = PARSER_TYPES[tool_id.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"Không có parser cho tool: {tool_id}") from exc
    return parser_type()


__all__ = [
    "AmcacheParserParser",
    "BaseParser",
    "EvtxECmdParser",
    "HayabusaParser",
    "MFTECmdParser",
    "PECmdParser",
    "PARSER_TYPES",
    "RECmdParser",
    "RowView",
    "create_parser",
]
