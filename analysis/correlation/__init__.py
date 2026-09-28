"""Correlation patterns that build suspected Incidents."""

from analysis.correlation.account_compromise import (
    AccountCompromiseCorrelation,
)
from analysis.correlation.correlation_engine import CorrelationEngine
from analysis.correlation.profiles import correlators_for_profile
from analysis.correlation.dos_attack import DosAttackCorrelation
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
    "correlators_for_profile",
    "DosAttackCorrelation",
    "EndpointCompromiseCorrelation",
    "IncidentBuilder",
    "LogTamperingCorrelation",
    "ServiceDisruptionCorrelation",
]
