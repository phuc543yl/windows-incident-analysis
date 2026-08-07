"""Domain exceptions for predictable error handling across the toolkit."""

from __future__ import annotations


class ToolkitError(Exception):
    """Base class for expected application errors."""


class ConfigurationError(ToolkitError):
    """Configuration is missing, malformed, or inconsistent."""


class JsonFileError(ToolkitError):
    """A JSON file could not be read, decoded, or written."""


class UnsafePathError(ToolkitError):
    """A path attempts to escape its permitted base directory."""


class CaseError(ToolkitError):
    """Base class for Case-management errors."""


class InvalidCaseIdError(CaseError):
    """A Case ID does not follow the required format."""


class CaseNotFoundError(CaseError):
    """The requested Case does not exist."""


class CaseAlreadyExistsError(CaseError):
    """A Case with the generated ID already exists."""


class CaseClosedError(CaseError):
    """An operation requires an open Case."""


class ClientError(ToolkitError):
    """A Local or Agent client operation failed."""


class ClientConnectionError(ClientError):
    """The Agent endpoint could not be reached."""


class CommandExecutionError(ClientError):
    """A local or remote command returned an execution failure."""


class CollectionError(ToolkitError):
    """Evidence collection failed."""


class CollectorNotFoundError(CollectionError):
    """A Collection Plan references an unknown collector."""


class EvidenceError(ToolkitError):
    """Evidence preservation or access failed."""


class IntegrityVerificationError(EvidenceError):
    """One or more evidence hashes do not match the manifest."""


class ToolIntegrationError(ToolkitError):
    """An external DFIR tool could not be validated or executed."""


class ProcessingError(ToolkitError):
    """Normalization, deduplication, or timeline processing failed."""


class AnalysisError(ToolkitError):
    """Finding, detection, or correlation processing failed."""


class ReportError(ToolkitError):
    """Report generation or export failed."""


class AgentError(ToolkitError):
    """Agent request processing failed."""


class AuthenticationError(AgentError):
    """Agent authentication failed."""
