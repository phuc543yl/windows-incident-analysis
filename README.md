# Windows Incident Analysis Toolkit

Bộ công cụ hỗ trợ thu thập, bảo toàn và phân tích bằng chứng phục vụ điều tra
sự cố an toàn thông tin trên Windows.

## Mục tiêu

Dự án tổ chức dữ liệu theo từng `Case`, hỗ trợ Local Mode và Agent Mode, tích
hợp các công cụ DFIR, chuẩn hóa kết quả, xây timeline và hỗ trợ chuyên viên xác
minh ảnh hưởng đến Confidentiality, Integrity và Availability.

Dự án không phải SIEM/EDR, không tự động ngăn chặn và không tự động xác nhận một
sự kiện đơn lẻ là sự cố.

## Trạng thái hiện tại

Giai đoạn đầu đã định nghĩa các entry point ở thư mục gốc:

- `main.py`: khởi động Tkinter Dashboard.
- `agent_main.py`: khởi động Agent API.
- `dfir_cli.py`: quản lý Case và chạy quy trình bằng dòng lệnh.
- `requirements.txt`: thư viện Python cần thiết.

Các entry point sử dụng import trễ. Vì vậy có thể tạo chúng trước các module
`ui`, `agent`, `case_management`, `collection`, `evidence`, `analysis` và
`reporting`. Khi module chưa tồn tại, chương trình trả về thông báo rõ ràng thay
vì traceback khó hiểu.

## Yêu cầu

- Windows 10/11 cho máy điều tra; Agent cần được kiểm thử riêng trên phiên bản
  Windows mục tiêu.
- Python phù hợp với hệ điều hành đang sử dụng.
- Quyền Administrator khi thu thập các artifact được bảo vệ.
- Các công cụ DFIR bên ngoài được đặt trong `tools/` và không commit file nhị
  phân lên Git.

## Cài đặt môi trường

Trong PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Nếu PowerShell chặn script kích hoạt, có thể gọi trực tiếp:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Các entry point

### Dashboard

```powershell
python main.py
```

Hợp đồng cần triển khai ở giai đoạn UI:

```python
# ui/main_window.py
def run_dashboard() -> int | None:
    ...
```

### Agent

```powershell
python agent_main.py --help
python agent_main.py --host 127.0.0.1 --port 8765
```

Mặc định Agent chỉ lắng nghe trên localhost. Chỉ mở Agent ra mạng lab sau khi
đã triển khai token, allowlist collector, timeout và audit log.

Hợp đồng ứng dụng:

```python
# agent/app.py
def create_app(config_path):
    ...
```

### CLI điều tra

```powershell
python dfir_cli.py --help
python dfir_cli.py case --help
python dfir_cli.py case create `
  --title "RDP account compromise" `
  --target "WIN-LAB01" `
  --mode local `
  --profile account_compromise
```

Các lệnh dự kiến:

```text
dfir_cli.py case create
dfir_cli.py case list
dfir_cli.py case show
dfir_cli.py case close
dfir_cli.py collect
dfir_cli.py verify
dfir_cli.py analyze
dfir_cli.py report
```

CLI xác lập các hợp đồng service sau:

| Service | Phương thức được entry point gọi |
|---|---|
| `CaseService` | `create_case`, `list_cases`, `open_case`, `close_case` |
| `CollectionService` | `collect_case` |
| `EvidenceService` | `verify_case` |
| `AnalysisService` | `analyze_case` |
| `ReportService` | `export_case` |

## Luồng MVP đầu tiên

```text
Tạo Case
  -> chọn Local Mode
  -> tạo Collection Plan
  -> thu System, Process, Network
  -> lưu acquisition/live/*.json
  -> tính SHA-256
  -> tạo manifest.json
```

Chỉ sau khi luồng này chạy ổn mới triển khai EVTX, tích hợp công cụ DFIR,
normalization, detection, correlation, Agent và UI hoàn chỉnh.

## Cấu trúc dự kiến

```text
tool_windows_forensic/
├── main.py
├── agent_main.py
├── dfir_cli.py
├── requirements.txt
├── README.md
├── config/
├── common/
├── models/
├── case_management/
├── clients/
├── collection/
├── evidence/
├── agent/
├── integrations/
├── processing/
├── analysis/
├── reporting/
├── ui/
├── tools/
├── runtime/
├── tests/
└── docs/
```

## Nguyên tắc bảo toàn bằng chứng

- Không ghi đè artifact gốc trong `acquisition/raw`.
- Tính SHA-256 ngay sau khi thu thập.
- Ghi nguồn, hostname, thời gian, kích thước, collector và người điều tra vào
  manifest.
- Kiểm tra hash trước khi phân tích lại.
- Lưu output công cụ và dữ liệu normalized tách khỏi bằng chứng gốc.
- Chỉ sử dụng dữ liệu thử nghiệm vô hại và máy ảo có snapshot khi demo.

## Công cụ DFIR dự kiến

- Hayabusa và EvtxECmd cho Windows Event Log.
- PECmd cho Prefetch.
- AmcacheParser cho Amcache.
- RECmd cho Registry Hive.
- MFTECmd cho `$MFT`.
- Memory acquisition và Volatility là phần mở rộng sau MVP.

## Bước triển khai tiếp theo

1. Tạo `common/`.
2. Tạo cấu hình tối thiểu.
3. Tạo các model nền tảng.
4. Viết `CaseService`.
5. Viết `LocalClient`.
6. Viết collector System, Process và Network.
7. Viết hash calculator và manifest builder.
8. Chạy luồng MVP bằng `dfir_cli.py`.
