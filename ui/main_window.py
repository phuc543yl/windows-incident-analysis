"""Main Tkinter dashboard that connects all project services."""

from __future__ import annotations

import os
import queue
import socket
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from clients.agent_client import AgentClient
from common.constants import APP_NAME, APP_VERSION
from common.exceptions import JsonFileError
from common.json_utils import read_json_object
from evidence.evidence_service import EvidenceService
from ui.components.status_bar import StatusBar
from ui.components.toolbar import Toolbar
from ui.theme import apply_theme
from ui.controllers import (
    AnalysisController,
    CaseController,
    CollectionController,
    IntegrationController,
    InvestigateController,
    ReportController,
)
from ui.tabs import (
    AgentTab,
    AnalysisTab,
    CaseTab,
    CollectionTab,
    EvidenceTab,
    InvestigateTab,
    OverviewTab,
    ReportTab,
    TimelineTab,
)


class MainWindow:
    """Desktop composition root; domain work remains inside services."""

    def __init__(
        self,
        root: tk.Tk,
        project_root: str | Path | None = None,
        *,
        actor: str | None = None,
    ) -> None:
        self.root = root
        self.project_root = (
            Path(project_root).resolve()
            if project_root is not None
            else Path(__file__).resolve().parents[1]
        )
        self._task_queue: queue.Queue[
            tuple[
                Callable[[Any], None] | None,
                Any,
                BaseException | None,
                str,
            ]
        ] = queue.Queue()
        self._busy_tasks = 0
        self._closed = False
        self._agent_process: subprocess.Popen | None = None
        self._agent_host = "127.0.0.1"
        self._agent_port = 8765

        self.case_controller = CaseController(
            self.project_root,
            actor=actor,
            on_case_changed=self._on_case_changed,
        )
        self.collection_controller = CollectionController(
            self.case_controller,
            self.project_root,
        )
        self.analysis_controller = AnalysisController(
            self.case_controller,
            self.project_root,
        )
        self.integration_controller = IntegrationController(
            self.case_controller,
            self.project_root,
            actor=actor or "analyst",
        )
        self.report_controller = ReportController(
            self.case_controller,
            self.project_root,
            actor=actor or "analyst",
        )
        self.investigate_controller = InvestigateController(
            self.case_controller,
            self.project_root,
            actor=actor or "analyst",
        )
        self.evidence_service = EvidenceService(
            self.project_root,
            actor=actor,
        )

        self._configure_window()
        self._build_interface()
        self._load_agent_configuration()
        self._refresh_case_list()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self._poll_tasks)
        self.root.after(250, self._ensure_lab_agent)

    def _configure_window(self) -> None:
        self.root.title(f"Crow-Eye — {APP_NAME} {APP_VERSION}")
        self.root.geometry("1280x820")
        self.root.minsize(1024, 680)
        apply_theme(self.root)

    def _build_interface(self) -> None:
        self.toolbar = Toolbar(
            self.root,
            on_new=self._new_case,
            on_refresh=self._refresh,
            on_collect=lambda: self._select_tab(self.collection_tab),
            on_analyze=lambda: self._select_tab(self.analysis_tab),
            on_report=lambda: self._select_tab(self.report_tab),
        )
        self.toolbar.pack(fill=tk.X)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        profiles = self.case_controller.service.profile_service.list_profiles()
        profile_ids = tuple(profile["profile_id"] for profile in profiles)

        self.case_tab = CaseTab(
            self.notebook,
            profile_ids=profile_ids,
            on_create=self._create_case,
            on_open=self._open_case,
            on_update=self._update_case,
            on_close=self._close_case,
        )
        self.collection_tab = CollectionTab(
            self.notebook,
            on_collect=self._collect,
        )
        self.evidence_tab = EvidenceTab(
            self.notebook,
            on_preserve=self._preserve_evidence,
            on_verify=self._verify_evidence,
            on_bundle=self._build_bundle,
        )
        self.overview_tab = OverviewTab(self.notebook)
        self.analysis_tab = AnalysisTab(
            self.notebook,
            on_process=self._process_raw_data,
            on_analyze=self._analyze,
            on_refresh=self._refresh_analysis,
            on_set_incident=self._set_incident_status,
        )
        self.investigate_tab = InvestigateTab(
            self.notebook,
            on_add_note=self._add_note,
            on_save_checklist=self._save_checklist,
            on_pivot=self._pivot_entity,
        )
        self.timeline_tab = TimelineTab(self.notebook)
        self.agent_tab = AgentTab(
            self.notebook,
            on_health_check=self._agent_health_check,
            on_start_agent=self._start_lab_agent,
        )
        self.report_tab = ReportTab(
            self.notebook,
            on_generate=self._generate_report,
        )

        for tab, title in (
            (self.case_tab, "Case"),
            (self.overview_tab, "Overview"),
            (self.collection_tab, "Collection"),
            (self.evidence_tab, "Evidence"),
            (self.analysis_tab, "Analysis"),
            (self.investigate_tab, "Investigate"),
            (self.timeline_tab, "Timeline"),
            (self.agent_tab, "Agent"),
            (self.report_tab, "Report"),
        ):
            self.notebook.add(tab, text=title)

        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _new_case(self) -> None:
        self.case_tab.show_new_form()
        self._select_tab(self.case_tab)
        self.status_bar.set_message("Nhập thông tin để tạo Case mới.")

    def _create_case(self, values: dict[str, Any]) -> None:
        self._safe_action(
            lambda: self.case_controller.create_case(**values),
            success="Đã tạo Case.",
        )

    def _open_case(self, case_id: str) -> None:
        self._safe_action(
            lambda: self.case_controller.select_case(case_id),
            success=f"Đã mở {case_id}.",
        )

    def _update_case(self, values: dict[str, Any]) -> None:
        self._safe_action(
            lambda: self.case_controller.update_current(**values),
            success="Đã cập nhật Case.",
        )

    def _close_case(self, conclusion: str) -> None:
        self._safe_action(
            lambda: self.case_controller.close_current(conclusion),
            success="Đã đóng Case.",
        )

    def _on_case_changed(self, context: dict[str, Any]) -> None:
        case_id = context["case"]["case_id"]
        self.toolbar.set_case(case_id)
        if hasattr(self, "status_bar"):
            self.status_bar.set_case(case_id)
        if hasattr(self, "case_tab"):
            self.case_tab.set_context(context)
            self.collection_tab.set_context(context)
            self._load_case_artifacts(case_id)
            self._refresh_case_list()

    def _load_case_artifacts(self, case_id: str) -> None:
        paths = self.case_controller.service.repository.paths(case_id)
        if paths.manifest_json.is_file():
            try:
                self.evidence_tab.set_manifest(
                    read_json_object(paths.manifest_json)
                )
            except JsonFileError as exc:
                self._show_error(exc)
        else:
            self.evidence_tab.set_manifest(
                {
                    "evidence_items": [],
                    "item_count": 0,
                    "total_size_bytes": 0,
                }
            )
        try:
            data = self.analysis_controller.refresh()
        except Exception:
            data = {
                "findings": [],
                "alerts": [],
                "incidents": [],
                "timeline": [],
            }
        self.analysis_tab.set_results(data)
        self.timeline_tab.set_events(data["timeline"])
        self._refresh_investigation_views(case_id, data)

    def _refresh_case_list(self) -> None:
        self.case_tab.set_cases(self.case_controller.list_cases())

    def _refresh(self) -> None:
        self._safe_action(self._refresh_all, success="Đã làm mới dữ liệu.")

    def _refresh_all(self) -> None:
        self._refresh_case_list()
        if self.case_controller.current_case_id:
            self.case_controller.refresh_current()

    def _collect(self, mode: str, agent_id: str | None) -> None:
        self._run_background(
            lambda: self.collection_controller.collect(
                mode=mode,
                agent_id=agent_id,
            ),
            self._collection_completed,
            "Đang thu thập artifact...",
        )

    def _collection_completed(
        self,
        results: tuple[dict[str, Any], ...],
    ) -> None:
        self.collection_tab.set_results(results)
        summary = self.collection_controller.summarize(results)
        self.status_bar.set_message(
            f"Thu thập xong: {summary['succeeded']} thành công, "
            f"{summary['failed']} thất bại."
        )

    def _preserve_evidence(self) -> None:
        self._run_background(
            lambda: self.evidence_service.preserve_case(
                self.case_controller.require_case_id()
            ),
            self._evidence_preserved,
            "Đang tính SHA-256 và tạo manifest...",
        )

    def _evidence_preserved(self, manifest: dict[str, Any]) -> None:
        self.evidence_tab.set_manifest(manifest)
        self.status_bar.set_message(
            f"Đã đăng ký {manifest.get('item_count', 0)} evidence."
        )

    def _verify_evidence(self) -> None:
        self._run_background(
            lambda: self.evidence_service.verify_case(
                self.case_controller.require_case_id()
            ),
            self._evidence_verified,
            "Đang kiểm tra toàn vẹn evidence...",
        )

    def _evidence_verified(self, result: dict[str, Any]) -> None:
        self.evidence_tab.set_verification(result)
        self.status_bar.set_message("Evidence toàn vẹn.")

    def _build_bundle(self) -> None:
        self._run_background(
            lambda: self.evidence_service.build_bundle(
                self.case_controller.require_case_id()
            ),
            lambda result: self.status_bar.set_message(
                f"Đã tạo bundle: {result.bundle_path.name}"
            ),
            "Đang tạo Evidence Bundle...",
        )

    def _analyze(self) -> None:
        self._run_background(
            self.analysis_controller.analyze,
            lambda _result: self._refresh_analysis(),
            "Đang chạy analyzer, rule và correlation...",
        )

    def _process_raw_data(self) -> None:
        self._run_background(
            self.integration_controller.process,
            self._raw_data_processed,
            "Đang chạy DFIR tools và chuẩn hóa dữ liệu...",
        )

    def _raw_data_processed(self, result: dict[str, Any]) -> None:
        self.analysis_tab.set_results(
            {
                "findings": [],
                "alerts": [],
                "incidents": [],
            }
        )
        self.timeline_tab.set_events(())
        succeeded = ", ".join(result["succeeded_tools"]) or "không có"
        message = (
            f"Đã xử lý {result['normalized_count']} records, "
            f"{result['timeline_count']} timeline events. "
            f"Live records: {result.get('live_record_count', 0)}. "
            f"Tools thành công: {succeeded}. "
            "Hãy bấm '2. Chạy phân tích'."
        )
        if result["warnings"]:
            message += f" Có {len(result['warnings'])} cảnh báo."
        self.status_bar.set_message(message)

    def _refresh_analysis(self) -> None:
        self._run_background(
            self.analysis_controller.refresh,
            self._analysis_refreshed,
            "Đang tải kết quả phân tích...",
        )

    def _analysis_refreshed(
        self,
        result: dict[str, list[dict[str, Any]]],
    ) -> None:
        self.analysis_tab.set_results(result)
        self.timeline_tab.set_events(result["timeline"])
        if self.case_controller.current_case_id:
            self._refresh_investigation_views(
                self.case_controller.current_case_id,
                result,
            )
        self.status_bar.set_message(
            f"{len(result['findings'])} findings | "
            f"{len(result['alerts'])} alerts | "
            f"{len(result['incidents'])} incidents"
        )

    def _set_incident_status(
        self,
        incident_id: str,
        status: str,
        conclusion: str,
        cia_impacts: tuple[str, ...],
    ) -> None:
        self._safe_action(
            lambda: self.analysis_controller.set_incident_status(
                incident_id,
                status,
                conclusion=conclusion,
                cia_impacts=cia_impacts,
            ),
            success="Đã lưu quyết định của chuyên viên.",
        )
        self._refresh_analysis()

    def _refresh_investigation_views(
        self,
        case_id: str,
        analysis: dict[str, Any],
    ) -> None:
        try:
            investigation = self.investigate_controller.load()
            tool_lines = self.investigate_controller.tool_health()
        except Exception as exc:
            investigation = {}
            tool_lines = (f"Không đọc được investigation: {exc}",)
        incidents = analysis.get("incidents") or []
        cia_values = []
        for incident in incidents:
            cia_values.extend(incident.get("cia_impacts") or [])
        context = self.case_controller.current_context or {}
        case = context.get("case") or {"case_id": case_id}
        hypothesis = case.get("hypothesis") or case.get("description") or ""
        next_steps = []
        if not analysis.get("alerts"):
            next_steps.append("Chạy xử lý dữ liệu thô rồi phân tích.")
        else:
            next_steps.append("Mở tab Investigate để xem story và MITRE.")
        if not cia_values:
            next_steps.append("Chưa Confirmed CIA — hoàn thành checklist trước.")
        next_steps.append("Xuất báo cáo HTML khi đã có kết luận.")
        self.overview_tab.set_overview(
            {
                "case": case,
                "evidence_count": len(
                    (self.evidence_tab.table._records if hasattr(self, "evidence_tab") else {})
                ),
                "integrity": "đã có manifest"
                if (self.case_controller.service.repository.paths(case_id).manifest_json.is_file())
                else "chưa có manifest",
                "finding_count": len(analysis.get("findings") or []),
                "alert_count": len(analysis.get("alerts") or []),
                "incident_count": len(incidents),
                "cia": ", ".join(str(item) for item in cia_values) or "chưa có",
                "hypothesis": hypothesis,
                "tool_lines": tool_lines,
                "next_steps": tuple(next_steps),
            }
        )
        self.investigate_tab.set_investigation(investigation)

    def _add_note(self, text: str) -> None:
        self._safe_action(
            lambda: self.investigate_tab.set_investigation(
                self.investigate_controller.add_note(text)
            ),
            success="Đã lưu ghi chú.",
        )

    def _save_checklist(self, items: list[dict[str, Any]]) -> None:
        self._safe_action(
            lambda: self.investigate_tab.set_investigation(
                self.investigate_controller.save_checklist(items)
            ),
            success="Đã lưu checklist.",
        )

    def _pivot_entity(self, entity_type: str, value: str) -> None:
        self._safe_action(
            lambda: self.investigate_tab.set_pivot_rows(
                self.investigate_controller.pivot(entity_type, value)
            ),
            success=f"Đã lọc {entity_type}={value}.",
        )

    def _generate_report(self, formats: tuple[str, ...]) -> None:
        self._run_background(
            lambda: self.report_controller.generate(formats),
            self._report_generated,
            "Đang xuất báo cáo...",
        )

    def _report_generated(self, result: dict[str, Any]) -> None:
        self.report_tab.set_result(result)
        self.status_bar.set_message(
            "Đã xuất: " + ", ".join(result["formats"]).upper()
        )

    def _load_agent_configuration(self) -> None:
        try:
            config = read_json_object(
                self.project_root / "config" / "agent.json"
            )
        except JsonFileError as exc:
            self.agent_tab.status_var.set(str(exc))
            return
        agent = config.get("agent", {})
        self._agent_host = str(agent.get("host") or "127.0.0.1")
        self._agent_port = int(agent.get("port") or 8765)
        self.agent_tab.set_configuration(config)
        self._refresh_agent_env_status()

    def _refresh_agent_env_status(self) -> None:
        from common.lab_env import describe_agent_token

        self.agent_tab.set_token_status(describe_agent_token())

    def _agent_reachable(self) -> bool:
        probe = socket.socket()
        probe.settimeout(0.4)
        try:
            return probe.connect_ex((self._agent_host, self._agent_port)) == 0
        except OSError:
            return False
        finally:
            probe.close()

    def _ensure_lab_agent(self) -> None:
        if self._closed or self._agent_reachable():
            return
        try:
            self._start_lab_agent()
        except Exception as exc:
            self.agent_tab.status_var.set(f"Chưa khởi động được Agent: {exc}")

    def _start_lab_agent(self) -> None:
        from common.lab_env import load_lab_env

        load_lab_env(self.project_root)
        self._refresh_agent_env_status()
        if self._agent_reachable():
            self.agent_tab.status_var.set("Agent lab đã sẵn sàng.")
            self.status_bar.set_message("Agent lab đang chạy.")
            return
        if self._agent_process is not None and self._agent_process.poll() is None:
            self.agent_tab.status_var.set("Agent lab đang khởi động...")
            return

        command = [
            sys.executable,
            str(self.project_root / "agent_main.py"),
            "--host",
            self._agent_host,
            "--port",
            str(self._agent_port),
        ]
        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        self._agent_process = subprocess.Popen(
            command,
            cwd=str(self.project_root),
            env=os.environ.copy(),
            creationflags=creationflags,
        )
        self.agent_tab.status_var.set("Đã mở Agent lab. Hãy kiểm tra kết nối.")
        self.status_bar.set_message(
            f"Đã khởi động Agent lab tại {self._agent_host}:{self._agent_port}."
        )

    def _agent_health_check(self) -> None:
        def operation() -> dict[str, Any]:
            client = AgentClient.from_config(
                self.project_root / "config" / "agent.json"
            )
            try:
                return client.health_check()
            finally:
                client.close()

        self._run_background(
            operation,
            self.agent_tab.set_health,
            "Đang kiểm tra Agent...",
        )

    def _safe_action(
        self,
        operation: Callable[[], Any],
        *,
        success: str,
    ) -> Any:
        try:
            result = operation()
        except Exception as exc:
            self._show_error(exc)
            return None
        self.status_bar.set_message(success)
        return result

    def _run_background(
        self,
        operation: Callable[[], Any],
        on_success: Callable[[Any], None] | None,
        message: str,
    ) -> None:
        self._busy_tasks += 1
        self.status_bar.set_busy(True, message)

        def worker() -> None:
            try:
                result = operation()
            except BaseException as exc:
                self._task_queue.put((on_success, None, exc, message))
            else:
                self._task_queue.put((on_success, result, None, message))

        threading.Thread(
            target=worker,
            name="crow-eye-ui-task",
            daemon=True,
        ).start()

    def _poll_tasks(self) -> None:
        while True:
            try:
                callback, result, error, _message = (
                    self._task_queue.get_nowait()
                )
            except queue.Empty:
                break
            self._busy_tasks = max(0, self._busy_tasks - 1)
            if error is not None:
                self._show_error(error)
            elif callback is not None:
                try:
                    callback(result)
                except Exception as exc:
                    self._show_error(exc)
        if self._busy_tasks == 0:
            self.status_bar.set_busy(False)
        if not self._closed:
            self.root.after(100, self._poll_tasks)

    def _show_error(self, error: BaseException) -> None:
        self.status_bar.set_message(f"Lỗi: {error}")
        messagebox.showerror("Crow-Eye", str(error), parent=self.root)

    def _select_tab(self, tab: ttk.Frame) -> None:
        self.notebook.select(tab)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        process = self._agent_process
        if process is not None and process.poll() is None:
            process.terminate()
        try:
            self.collection_controller.close()
        finally:
            self.root.destroy()


def run_dashboard(
    project_root: str | Path | None = None,
    *,
    actor: str | None = None,
) -> int:
    """Create and run the Tk event loop."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError(
            "Không thể khởi tạo Tkinter. Hãy chạy trong phiên desktop "
            "có màn hình và kiểm tra Python đã cài Tcl/Tk."
        ) from exc
    MainWindow(root, project_root, actor=actor)
    root.mainloop()
    return 0
