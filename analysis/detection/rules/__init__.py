"""Detection rule implementations."""

from analysis.detection.rules.base_rule import BaseRule
from analysis.detection.rules.failed_logon_burst import (
    FailedLogonBurstRule,
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
}

__all__ = [
    "BaseRule",
    "RULE_TYPES",
    "FailedLogonBurstRule",
    "RegistryAutorunChangeRule",
    "ScheduledTaskCreatedRule",
    "SecurityLogClearedRule",
    "ServiceConfigurationChangedRule",
    "ServiceStoppedRule",
    "SuccessfulLogonAfterFailuresRule",
    "SuspiciousFileExecutionRule",
    "SuspiciousPowerShellRule",
]
