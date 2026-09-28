"""Map investigation profiles to the correlators they may run."""

from __future__ import annotations

from analysis.correlation.account_compromise import (
    AccountCompromiseCorrelation,
)
from analysis.correlation.dos_attack import DosAttackCorrelation
from analysis.correlation.endpoint_compromise import (
    EndpointCompromiseCorrelation,
)
from analysis.correlation.log_tampering import LogTamperingCorrelation
from analysis.correlation.service_disruption import (
    ServiceDisruptionCorrelation,
)

ALL_CORRELATORS = (
    AccountCompromiseCorrelation(),
    EndpointCompromiseCorrelation(),
    LogTamperingCorrelation(),
    ServiceDisruptionCorrelation(),
    DosAttackCorrelation(),
)

_PROFILE_TO_TYPES = {
    "general_investigation": None,
    "general": None,
    "account_compromise": ("account_compromise",),
    "endpoint_compromise": ("endpoint_compromise",),
    "log_tampering": ("log_tampering",),
    "service_disruption": ("service_disruption",),
    "dos_attack": ("dos_attack",),
    "dos_availability": ("dos_attack",),
}

_TYPE_TO_CORRELATOR = {
    "account_compromise": AccountCompromiseCorrelation,
    "endpoint_compromise": EndpointCompromiseCorrelation,
    "log_tampering": LogTamperingCorrelation,
    "service_disruption": ServiceDisruptionCorrelation,
    "dos_attack": DosAttackCorrelation,
}


def correlators_for_profile(profile_id: str | None):
    """Return correlator instances allowed for one investigation profile."""
    if not profile_id:
        return ALL_CORRELATORS
    normalized = str(profile_id).strip().casefold()
    selected = _PROFILE_TO_TYPES.get(normalized)
    if selected is None:
        return ALL_CORRELATORS
    return tuple(_TYPE_TO_CORRELATOR[name]() for name in selected)
