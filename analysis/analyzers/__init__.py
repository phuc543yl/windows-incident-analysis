"""Context analyzers used before rule evaluation."""

from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.analyzers.event_analyzer import EventAnalyzer
from analysis.analyzers.execution_analyzer import ExecutionAnalyzer
from analysis.analyzers.network_analyzer import NetworkAnalyzer
from analysis.analyzers.process_analyzer import ProcessAnalyzer
from analysis.analyzers.registry_analyzer import RegistryAnalyzer
from analysis.analyzers.service_analyzer import ServiceAnalyzer

DEFAULT_ANALYZERS = (
    EventAnalyzer(),
    ProcessAnalyzer(),
    NetworkAnalyzer(),
    RegistryAnalyzer(),
    ExecutionAnalyzer(),
    ServiceAnalyzer(),
)

__all__ = [
    "BaseAnalyzer",
    "DEFAULT_ANALYZERS",
    "EventAnalyzer",
    "ExecutionAnalyzer",
    "NetworkAnalyzer",
    "ProcessAnalyzer",
    "RegistryAnalyzer",
    "ServiceAnalyzer",
]
