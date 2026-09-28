# Crow-Eye - 4 Case mẫu có Ground Truth

Bộ dữ liệu này bổ sung 4 Case reference để mở trực tiếp trên Dashboard Crow-Eye.
Dữ liệu là **sample có Ground Truth**, được dựng theo schema thật của Crow-Eye; không phải
EVTX/capture lấy từ một lần tấn công VM thật. Mục tiêu là cho bạn kiểm tra luồng Case ->
Evidence -> Normalized -> Alert -> Incident -> Report trước khi chạy thực nghiệm Win8.

## Cài vào dự án

Giải nén nội dung ZIP trực tiếp vào thư mục gốc dự án Crow-Eye. Các file đều là file mới; thư mục
`runtime/cases` sẽ được merge với runtime hiện có. Sau đó mở Dashboard và bấm **Làm mới**.

| Case | Kịch bản | Rule kỳ vọng | Incident | CIA |
|---|---|---|---|---|
| CASE-20260808-901 | DoS | connection_flood | dos_attack | Availability |
| CASE-20260808-902 | PowerShell Anti-Forensics / Security log cleared | security_log_cleared, suspicious_powershell | log_tampering | Integrity |
| CASE-20260808-903 | Scheduled Task Persistence + thay đổi file | scheduled_task_created, suspicious_powershell | endpoint_compromise | Integrity |
| CASE-20260808-904 | Unauthorized Windows Service Disruption | service_configuration_changed, service_stopped | service_disruption | Availability |

## Mỗi Case có gì

- `case.json`, `target.json`, `collection_plan.json` đúng model Crow-Eye.
- `acquisition/`: snapshot evidence, manifest, SHA-256 và chain of custody.
- `analysis/normalized/records.json` và `analysis/timeline.json`.
- `analysis/findings.json`, `alerts.json`, `incidents.json`; Incident đã Confirmed theo Ground Truth.
- `analyst/ground_truth.json`, notes, conclusion, recommendations và `experiment_results.json`.
- `reports/investigation_report.html`, JSON và timeline CSV.

## Protocol thực nghiệm thật trên Windows 8 VM

1. Tạo snapshot sạch của VM, đồng bộ thời gian và ghi baseline hostname/IP/service/file/log count.
2. Thu evidence **trước** sự cố; ghi SHA-256, timestamp và trạng thái dịch vụ/file.
3. Chỉ kích hoạt **một** kịch bản trong mạng host-only cô lập, có quyền hoàn nguyên snapshot.
4. Thu evidence ngay sau sự kiện bằng Agent/Crow-Eye; không sửa evidence đã hash.
5. Chạy normalized pipeline -> Phân tích -> đối chiếu Alert/Incident với Ground Truth.
6. Ghi TP/FP/FN để tính Precision/Recall; đo collection, processing, analysis time và dung lượng Case.
7. Hoàn nguyên snapshot trước khi chuyển sang kịch bản kế tiếp.

### 1. DoS

Ground Truth cần có: nguồn phát trong lab, IP/port đích, connection count theo cửa sổ thời gian,
probe dịch vụ trước = success và trong sự cố = timeout/degraded. Case mẫu dùng 120 kết nối / 5.95 s
vào port 8080 và kỳ vọng một `connection_flood` -> một `dos_attack`.

### 2. PowerShell Anti-Forensics - Security Event Log bị xóa

Chỉ chạy trên snapshot VM. Ground Truth cần lưu trạng thái/count Security log trước thao tác, dấu vết
PowerShell và Event ID 1102 sau thao tác. Việc live Security log mất lịch sử trước đó là bằng chứng
tác động **Integrity** của audit trail. Ưu tiên thêm log forwarding/SIEM để có bản sao ngoài endpoint.

### 3. Scheduled Task Persistence gây thay đổi dữ liệu

Tạo một Scheduled Task lab và một file kiểm thử có baseline SHA-256. Sau khi task chạy, chứng minh
file thay đổi bằng SHA-256 mới, đồng thời lưu Event 4698, task XML và tiến trình con. Ground Truth
phải nối được Task -> Process -> File change; CIA = **Integrity**.

### 4. Unauthorized Windows Service Disruption

Dùng service lab riêng. Baseline = Running/Automatic và probe thành công; sự kiện = đổi Startup Type
ngoài change window + dừng service; hậu kiểm = Stopped/Disabled và probe thất bại. Đối chiếu Event
7040 + 7036; CIA = **Availability**.

## Đo Ground Truth bằng code hiện có

Bốn file mới trong `tests/fixtures/ground_truth/` có thể chạy bằng `experiments.ground_truth`.
Không dùng timing của sample làm số liệu luận văn; hãy chạy suite/pipeline trên môi trường bạn công bố
trong Chương thực nghiệm và lưu raw results.

## Kết quả tự kiểm tra khi tạo gói

- CASE-20260808-901: 123 normalized, 1 alerts, 1 incidents, evidence_integrity_verified=True.
- CASE-20260808-902: 3 normalized, 2 alerts, 1 incidents, evidence_integrity_verified=True.
- CASE-20260808-903: 3 normalized, 2 alerts, 1 incidents, evidence_integrity_verified=True.
- CASE-20260808-904: 3 normalized, 2 alerts, 1 incidents, evidence_integrity_verified=True.

Lưu ý: Case DoS cần `connection_flood` rule và `dos_attack` correlation đã được thêm vào Crow-Eye.
Nếu project của bạn chưa có hai phần đó, Case vẫn mở được nhưng re-analysis DoS sẽ không sinh incident.
