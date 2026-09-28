# Crow-Eye

Crow-Eye là bộ công cụ hỗ trợ thu thập, bảo toàn và phân tích bằng chứng
phục vụ điều tra sự cố an toàn thông tin trên Windows.

Công cụ tổ chức dữ liệu theo từng `Case`, hỗ trợ Local Mode và Agent Mode,
chuẩn hóa kết quả, dựng timeline, chạy detection/correlation, rồi để chuyên
viên xác nhận tác động Confidentiality, Integrity và Availability.

Crow-Eye **không phải** SIEM/EDR, không tự động ngăn chặn và không tự xác nhận
một sự kiện đơn lẻ là sự cố. Incident tự động luôn ở trạng thái `suspected`.

## Trạng thái hiện tại (1.0.0)

Đã triển khai đủ luồng đồ án:

- Dashboard Tkinter: Case, Overview, Collection, Evidence, Analysis,
  Investigate, Timeline, Agent, Report.
- CLI `dfir_cli.py` cho tạo Case, thu thập, verify, process, analyze, report.
- Agent HTTP cục bộ với token, allowlist collector và Evidence Bundle.
- 15 collector, 6 analyzer, 14 detection rule, 5 correlation pattern.
- Báo cáo HTML/PDF/JSON/CSV, story timeline, bảng MITRE, baseline diff,
  checklist và ghi chú chuyên viên.

## Yêu cầu

- Windows 10/11 cho máy điều tra; Agent cần được kiểm thử trên máy mục tiêu.
- Python 3.11+ (hoặc phiên bản tương thích với `requirements.txt`).
- Quyền Administrator khi thu thập artifact được bảo vệ.
- Công cụ DFIR bên ngoài đặt trong `tools/` và không commit file nhị phân.

## Cài đặt

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Chạy

```powershell
# Dashboard
.\.venv\Scripts\python.exe main.py

# CLI
.\.venv\Scripts\python.exe dfir_cli.py --help
.\.venv\Scripts\python.exe dfir_cli.py case list

# Agent (localhost). Token lab được nạp từ .env.lab
.\.venv\Scripts\python.exe agent_main.py --host 127.0.0.1 --port 8765
```

`main.py`, `agent_main.py` và `dfir_cli.py` tự nạp file `.env.lab` ở thư mục
gốc. Bản lab mặc định dùng `WINDOWS_FORENSIC_AGENT_TOKEN=croweye-lab-2026`.
Mẫu nằm tại `config/lab.env.example`. Token không được ghi vào
`config/agent.json`. Trên tab Agent, bấm **Khởi động Agent lab** rồi
**Kiểm tra kết nối**.

Bốn case mẫu nằm tại `runtime/cases/CASE-20260808-901` đến `904`.
Mở Dashboard, bấm **Làm mới**, rồi mở Case để xem Evidence → Analysis →
Investigate → Report.

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m experiments.run_ground_truth
```

Số liệu Precision/Recall trên fixture tổng hợp chỉ dùng để hồi quy. Chương
thực nghiệm luận văn phải đo lại trên VM lab với evidence thật và tập benign.

## Nguyên tắc bảo toàn bằng chứng

- Không ghi đè artifact gốc trong `acquisition/raw`.
- Tính SHA-256 ngay sau khi thu thập và verify trước khi phân tích lại.
- Timestamp chuẩn UTC ISO 8601; đường dẫn trong JSON là tương đối, không có `..`.
- Demo chỉ chạy trong lab được phép, ưu tiên máy ảo có snapshot.

## Giới hạn đã biết

- Detection vẫn là rule-based, không thay thế Sigma/Hayabusa đầy đủ.
- Memory collector chỉ import image đã có; chưa dump RAM hay chạy Volatility.
- Network live là snapshot; kịch bản DoS thuyết phục hơn khi có nhiều mẫu
  hoặc log tường lửa / fixture có timestamp.
- Agent mặc định chỉ bind localhost, dùng cho lab.
