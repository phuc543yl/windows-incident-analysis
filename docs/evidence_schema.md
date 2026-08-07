# Schema bằng chứng và dữ liệu phân tích

## 1. Quy ước chung

Các file JSON của dự án dùng UTF-8, object ở cấp cao nhất và
`schema_version: 1`. Timestamp được chuẩn hóa về UTC ISO 8601 với hậu tố `Z`.
Đường dẫn trong dữ liệu là đường dẫn tương đối kiểu POSIX, dùng `/`, không
chứa ổ đĩa, đường dẫn tuyệt đối hoặc thành phần `..`.

Phân loại dữ liệu:

| Category | Giá trị | Ý nghĩa |
|---|---|---|
| Live | `live` | Ảnh chụp trạng thái system, users, processes, network, services, startup |
| Raw artifact | `raw_artifact` | EVTX, Prefetch, Amcache, Registry, `$MFT`, Scheduled Task, firewall log, file hoặc memory |
| Tool output | `tool_output` | CSV/JSON/JSONL và stdout/stderr do công cụ DFIR tạo |
| Normalized | `normalized` | Bản ghi chung sau khi parser và pipeline xử lý |
| Report | `report` | Dữ liệu trình bày được xuất từ trạng thái Case |

## 2. Manifest của Case

`acquisition/manifest.json` là object mô tả tập bằng chứng mà máy điều tra đã
đăng ký. Local Mode, Agent Mode và máy phân tích dùng chung chính xác schema
này; Agent không có biến thể manifest rút gọn riêng.

### 2.1. Trường cấp cao nhất

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---:|---|
| `schema_version` | integer | Có | Phiên bản schema, hiện là `1` |
| `case_id` | string | Có | ID dạng `CASE-YYYYMMDD-NNN` |
| `generated_at` | timestamp | Có | Thời điểm tạo manifest |
| `generated_by` | string | Có | Chuyên viên hoặc tác nhân tạo |
| `hash_algorithm` | string | Có | Luôn là `sha256` |
| `item_count` | integer | Có | Số phần tử trong `evidence_items` |
| `total_size_bytes` | integer | Có | Tổng kích thước bằng chứng |
| `evidence_items` | array | Có | Danh sách `EvidenceItem` |

### 2.2. EvidenceItem

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---:|---|
| `case_id` | string | Có | Case sở hữu item |
| `evidence_id` | string | Có | ID ổn định bắt đầu bằng `EVID-` |
| `artifact_type` | string | Có | Một giá trị của `ArtifactType` |
| `category` | string | Có | `live` hoặc `raw_artifact` khi đăng ký acquisition |
| `source_path` | string | Có | Nguồn logic hoặc đường dẫn nguồn đã chuẩn hóa |
| `stored_path` | string | Có | Vị trí tương đối trong Case |
| `collector_id` | string | Có | Collector tạo hoặc sao chép item |
| `hostname` | string | Có | Endpoint nguồn |
| `sha256` | string | Có | 64 ký tự hexadecimal chữ thường |
| `size_bytes` | integer | Có | Kích thước không âm |
| `collected_at` | timestamp | Có | Thời điểm thu thập/ghi nhận |
| `source_created_at` | timestamp/null | Không | Thời gian tạo ở nguồn nếu có |
| `source_modified_at` | timestamp/null | Không | Thời gian sửa ở nguồn nếu có |
| `metadata` | object | Có | Thuộc tính mở rộng, ví dụ `collected_by` |

Ví dụ manifest tối thiểu:

```json
{
  "schema_version": 1,
  "case_id": "CASE-20260729-001",
  "generated_at": "2026-07-29T08:10:00.000Z",
  "generated_by": "analyst",
  "hash_algorithm": "sha256",
  "item_count": 1,
  "total_size_bytes": 128,
  "evidence_items": [
    {
      "case_id": "CASE-20260729-001",
      "evidence_id": "EVID-111111111111111111111111",
      "artifact_type": "event_logs",
      "category": "raw_artifact",
      "source_path": "Windows/System32/winevt/Logs/Security.evtx",
      "stored_path": "acquisition/raw/EventLogs/Security.evtx",
      "collector_id": "event_logs",
      "hostname": "WIN-LAB01",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size_bytes": 128,
      "collected_at": "2026-07-29T08:09:30.000Z",
      "source_created_at": null,
      "source_modified_at": null,
      "metadata": {
        "collected_by": "analyst",
        "source_path_inferred": false
      }
    }
  ]
}
```

## 3. Danh sách SHA-256

`acquisition/hashes.sha256` có một dòng cho mỗi item:

```text
<64-hex-sha256><hai dấu cách><stored_path>
```

Ví dụ:

```text
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  acquisition/raw/EventLogs/Security.evtx
```

Thứ tự dòng ổn định theo `stored_path`. Hash phải được kiểm tra lại trước khi
phân tích lại, xuất bundle hoặc dựa vào bằng chứng để kết luận.

## 4. Chain of custody

`acquisition/chain_of_custody.json` ghi lịch sử đăng ký và xử lý evidence.
Việc tạo lại manifest không tạo bản ghi `evidence_registered` trùng cho cùng
`evidence_id`.

```json
{
  "schema_version": 1,
  "case_id": "CASE-20260729-001",
  "entries": [
    {
      "timestamp": "2026-07-29T08:10:00.000Z",
      "action": "evidence_registered",
      "actor": "analyst",
      "evidence_id": "EVID-111111111111111111111111",
      "stored_path": "acquisition/raw/EventLogs/Security.evtx",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "size_bytes": 128,
      "collector_id": "event_logs",
      "hostname": "WIN-LAB01"
    }
  ],
  "updated_at": "2026-07-29T08:10:00.000Z"
}
```

## 5. Collection result

Mỗi collector tạo một `CollectionResult` trong `logs/collection.log` hoặc trong
metadata của Agent task.

| Trường | Nội dung |
|---|---|
| `case_id`, `plan_id`, `collector_id`, `result_id` | Liên kết lần thu thập |
| `status` | `pending`, `running`, `succeeded`, `partial` hoặc `failed` |
| `started_at`, `finished_at` | Khoảng thời gian chạy |
| `record_count` | Số bản ghi live hoặc số phần tử collector báo cáo |
| `evidence_item_ids` | Evidence liên quan sau khi đăng ký |
| `warnings`, `errors` | Cảnh báo/lỗi đã làm sạch |
| `metadata.output_paths` | File tương đối đã ghi trong Case |

`partial` biểu thị collector có output nhưng kèm cảnh báo; nó không đồng nghĩa
với thất bại hoàn toàn.

## 6. NormalizedRecord

Parser của các công cụ và collector chuyển dữ liệu khác nhau về schema chung:

```json
{
  "case_id": "CASE-20260729-001",
  "source_type": "evtxecmd_event",
  "artifact_type": "event_logs",
  "timestamp": "2026-07-29T08:05:00.000Z",
  "summary": "RDP logon succeeded after failures",
  "record_id": "REC-ACCOUNT-SUCCESS-01",
  "hostname": "WIN-LAB01",
  "user": "labuser",
  "event_id": 4624,
  "process_id": null,
  "parent_process_id": null,
  "process_name": "",
  "source_ip": "203.0.113.10",
  "destination_ip": "",
  "file_path": "",
  "raw_reference": "analysis/tool_outputs/evtxecmd/account.csv",
  "attributes": {
    "LogonType": 10,
    "TargetUserName": "labuser"
  }
}
```

Các trường thực thể có thể rỗng nếu artifact nguồn không cung cấp chúng.
`attributes` giữ dữ liệu nguồn cần thiết cho rule và truy vết. `raw_reference`
phải trỏ tới dữ liệu nguồn/dẫn xuất trong Case, không phải URL hoặc đường dẫn
tuyệt đối.

## 7. TimelineEvent

`analysis/timeline.json` sắp xếp sự kiện theo `timestamp`, `sort_priority` và ID
ổn định. Một timeline event chứa:

- `timeline_event_id`, `case_id`, `timestamp`, `event_type`, `summary`;
- `hostname`, `user`;
- `source_record_ids`, `finding_ids`, `alert_ids`, `evidence_item_ids`;
- `sort_priority` và `details`.

Timeline là lớp điều hướng bằng chứng. Nó không tự chứng minh quan hệ nhân quả;
correlation mới đánh giá chuỗi điều kiện theo thời gian và thực thể.

## 8. Finding, Alert và Incident

| Đối tượng | Vai trò | Trường liên kết chính |
|---|---|---|
| `Finding` | Quan sát đáng chú ý từ analyzer/rule | record IDs, evidence IDs, MITRE, confidence |
| `Alert` | Kết quả rule có severity và risk score | finding IDs, record IDs, recommendation |
| `Incident` | Giả thuyết tương quan cần chuyên viên xác minh | alert/finding/timeline IDs, status, CIA |

Incident mới tạo có trạng thái `suspected` và `cia_impacts` rỗng. Chỉ
`AnalysisService.set_incident_status` cùng kết luận của chuyên viên mới chuyển
nó thành `confirmed` và gán `confidentiality`, `integrity` hoặc `availability`.

## 9. Evidence Bundle

ZIP dùng đường dẫn tương đối kiểu POSIX và tối thiểu phải chứa
`acquisition/manifest.json`. Bundle do Agent tạo còn chứa:

- `collection_plan.json`;
- `collection_results.json`;
- `acquisition/live/**` và `acquisition/raw/**`;
- `acquisition/manifest.json`;
- `acquisition/hashes.sha256`;
- `acquisition/chain_of_custody.json`.

Manifest trong Agent Bundle phải parse được trực tiếp bằng cùng
`EvidenceManifest`/`EvidenceItem` mà máy phân tích sử dụng. Vì vậy mỗi item từ
Agent cũng bắt buộc có `case_id`, `evidence_id`, `artifact_type`, `category`,
`source_path`, `stored_path`, `collector_id`, `hostname`, hash, kích thước và
timestamp thu thập.

`BundleReader` từ chối entry tuyệt đối, `..`, dấu `\`, symbolic link, file mã
hóa, entry trùng, CRC lỗi, kích thước vượt giới hạn hoặc tỷ lệ nén bất thường.
SHA-256 của chính file ZIP được kiểm tra độc lập với hash của các member.

## 10. Quy tắc thay đổi schema

1. Không đổi ý nghĩa trường đang tồn tại trong cùng `schema_version`.
2. Trường mới phải có giá trị mặc định để đọc dữ liệu cũ.
3. Thay đổi phá vỡ tương thích phải tăng `schema_version` và thêm migration.
4. Fixture và unit test phải được cập nhật cùng thay đổi schema.
5. Không xóa `raw_reference`, ID liên kết hoặc hash chỉ để làm báo cáo gọn hơn.
