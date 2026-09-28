"""Application-wide constants.

This module intentionally contains values only. Filesystem resolution, logging,
and configuration loading belong to their dedicated modules.
"""

from __future__ import annotations

from typing import Final

APP_NAME: Final = "Crow-Eye"
APP_FULL_NAME: Final = "Crow-Eye Windows Incident Analysis Toolkit"
APP_SHORT_NAME: Final = "CrowEye"
APP_VERSION: Final = "1.0.0"
APP_LOGGER_NAME: Final = "windows_forensic"

DEFAULT_ENCODING: Final = "utf-8"
DEFAULT_HASH_ALGORITHM: Final = "sha256"
DEFAULT_LOG_LEVEL: Final = "INFO"
DEFAULT_AGENT_HOST: Final = "127.0.0.1"
DEFAULT_AGENT_PORT: Final = 8765
DEFAULT_COLLECTION_TIMEOUT_SECONDS: Final = 120

CASE_ID_PREFIX: Final = "CASE"
CASE_ID_DATE_FORMAT: Final = "%Y%m%d"
CASE_ID_SEQUENCE_WIDTH: Final = 3

CONFIG_DIRECTORY_NAME: Final = "config"
TOOLS_DIRECTORY_NAME: Final = "tools"
RUNTIME_DIRECTORY_NAME: Final = "runtime"
CASES_DIRECTORY_NAME: Final = "cases"
AGENT_BUFFER_DIRECTORY_NAME: Final = "agent_buffer"
LOGS_DIRECTORY_NAME: Final = "logs"

CASE_ACQUISITION_DIRECTORY_NAME: Final = "acquisition"
CASE_LIVE_DIRECTORY_NAME: Final = "live"
CASE_RAW_DIRECTORY_NAME: Final = "raw"
CASE_BUNDLES_DIRECTORY_NAME: Final = "bundles"
CASE_ANALYSIS_DIRECTORY_NAME: Final = "analysis"
CASE_ANALYST_DIRECTORY_NAME: Final = "analyst"
CASE_REPORTS_DIRECTORY_NAME: Final = "reports"

MANIFEST_FILE_NAME: Final = "manifest.json"
HASHES_FILE_NAME: Final = "hashes.sha256"
CHAIN_OF_CUSTODY_FILE_NAME: Final = "chain_of_custody.json"

SUPPORTED_LIVE_COLLECTORS: Final[tuple[str, ...]] = (
    "system",
    "users",
    "processes",
    "network",
    "services",
    "startup",
)

SUPPORTED_ARTIFACT_COLLECTORS: Final[tuple[str, ...]] = (
    "event_logs",
    "prefetch",
    "amcache",
    "registry",
    "mft",
    "scheduled_tasks",
    "firewall_logs",
    "files",
    "memory",
)

SUPPORTED_REPORT_FORMATS: Final[tuple[str, ...]] = (
    "html",
    "pdf",
    "json",
    "csv",
)

MAX_LOG_BYTES: Final = 5 * 1024 * 1024
LOG_BACKUP_COUNT: Final = 5
