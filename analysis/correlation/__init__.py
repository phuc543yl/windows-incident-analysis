"""Correlation patterns that build suspected Incidents."""

from analysis.correlation.account_compromise import (
    AccountCompromiseCorrelation,
)
from analysis.correlation.correlation_engine import CorrelationEngine
from analysis.correlation.endpoint_compromise import (
    EndpointCompromiseCorrelation,
)
from analysis.correlation.incident_builder import IncidentBuilder
from analysis.correlation.log_tampering import LogTamperingCorrelation
from analysis.correlation.service_disruption import (
    ServiceDisruptionCorrelation,
)

__all__ = [
    "AccountCompromiseCorrelation",
    "CorrelationEngine",
    "EndpointCompromiseCorrelation",
    "IncidentBuilder",
    "LogTamperingCorrelation",
    "ServiceDisruptionCorrelation",
]
