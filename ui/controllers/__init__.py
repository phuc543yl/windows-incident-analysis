"""UI controllers that coordinate application services."""

from ui.controllers.analysis_controller import AnalysisController
from ui.controllers.case_controller import CaseController
from ui.controllers.collection_controller import CollectionController
from ui.controllers.integration_controller import IntegrationController
from ui.controllers.investigate_controller import InvestigateController
from ui.controllers.report_controller import ReportController


class CurrentCaseRequiredError(RuntimeError):
    """Raised when an action requires a selected Case."""


__all__ = [
    "AnalysisController",
    "CaseController",
    "CollectionController",
    "CurrentCaseRequiredError",
    "IntegrationController",
    "InvestigateController",
    "ReportController",
]
