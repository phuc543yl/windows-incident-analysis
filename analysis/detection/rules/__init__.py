"""Detection rule implementations."""

from analysis.detection.rules.base_rule import BaseRule
from analysis.detection.rules.connection_flood import ConnectionFloodRule
from analysis.detection.rules.event_log_service_shutdown import (
    EventLogServiceShutdownRule,
)
from analysis.detection.rules.failed_logon_burst import (
    FailedLogonBurstRule,
)
from analysis.detection.rules.file_integrity_change import (
    FileIntegrityChangeRule,
)
from analysis.detection.rules.powershell_scriptblock import (
    PowerShellScriptBlockRule,
)
from analysis.detection.rules.registry_autorun_change import (
    RegistryAutorunChangeRule,
)
from analysis.detection.rules.scheduled_task_created import (
    ScheduledTaskCreatedRule,
)
from analysis.detection.rules.security_log_cleared import (
    SecurityLogClearedRule,
)
from analysis.detection.rules.service_configuration_changed import (
    ServiceConfigurationChangedRule,
)
from analysis.detection.rules.service_probe_failed import (
    ServiceProbeFailedRule,
)
from analysis.detection.rules.service_stopped import ServiceStoppedRule
from analysis.detection.rules.successful_logon_after_failures import (
    SuccessfulLogonAfterFailuresRule,
)
from analysis.detection.rules.suspicious_file_execution import (
    SuspiciousFileExecutionRule,
)
from analysis.detection.rules.suspicious_powershell import (
    SuspiciousPowerShellRule,
)

RULE_TYPES = {
    "failed_logon_burst": FailedLogonBurstRule,
    "successful_logon_after_failures": (
        SuccessfulLogonAfterFailuresRule
    ),
    "suspicious_powershell": SuspiciousPowerShellRule,
    "registry_autorun_change": RegistryAutorunChangeRule,
    "scheduled_task_created": ScheduledTaskCreatedRule,
    "suspicious_file_execution": SuspiciousFileExecutionRule,
    "security_log_cleared": SecurityLogClearedRule,
    "service_stopped": ServiceStoppedRule,
    "service_configuration_changed": ServiceConfigurationChangedRule,
    "connection_flood": ConnectionFloodRule,
    "event_log_service_shutdown": EventLogServiceShutdownRule,
    "powershell_scriptblock_suspicious": PowerShellScriptBlockRule,
    "file_integrity_change": FileIntegrityChangeRule,
    "service_probe_failed": ServiceProbeFailedRule,
}

__all__ = [
    "BaseRule",
    "RULE_TYPES",
    "ConnectionFloodRule",
    "EventLogServiceShutdownRule",
    "FailedLogonBurstRule",
    "FileIntegrityChangeRule",
    "PowerShellScriptBlockRule",
    "ServiceProbeFailedRule",
    "RegistryAutorunChangeRule",
    "ScheduledTaskCreatedRule",
    "SecurityLogClearedRule",
    "ServiceConfigurationChangedRule",
    "ServiceStoppedRule",
    "SuccessfulLogonAfterFailuresRule",
    "SuspiciousFileExecutionRule",
    "SuspiciousPowerShellRule",
]
