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

Case được tạo và lưu cục bộ trong `runtime/cases/`; dữ liệu runtime không có
trong repository. Các kịch bản mẫu dùng để kiểm thử nằm trong
`tests/fixtures/scenarios/` và `tests/fixtures/ground_truth/`.

Trong tab **Analysis**, bấm **1. Xử lý dữ liệu thô** hoặc **2. Chạy phân tích**
để mở hộp thoại tiến trình. Hộp thoại hiển thị bước đang chạy, công cụ/bộ phân
tích hiện tại, nhật ký từng bước và thời gian chạy. Thanh hoạt động chạy trong
khi xử lý; trạng thái hoàn tất hoặc lỗi được giữ lại để xem, sau đó bấm **Đóng**.
Trong lúc chạy, hộp thoại khóa thao tác trên cửa sổ chính để tránh đổi Case
hoặc chạy trùng tác vụ. Khi xử lý dữ liệu thô, công cụ bị bỏ qua/thất bại cũng
được ghi vào nhật ký.

Nút **Bắt đầu thu thập** trong tab **Collection** cũng mở hộp thoại tiến trình,
hiển thị collector đang chạy, kết quả từng mục và cảnh báo/lỗi. Với Agent Mode,
cập nhật các file trong thư mục `agent/` trên máy Agent và khởi động lại Agent
để hiển thị collector hiện tại; Agent phiên bản cũ vẫn hiển thị trạng thái tác
vụ cùng các bước tải và nhập Evidence Bundle.

Local Mode tự đăng ký manifest và kiểm tra SHA-256 sau thu thập. Khi thu thập
lại trong cùng Case, Crow-Eye kiểm tra bằng chứng hiện tại trước, lưu toàn bộ
bằng chứng và metadata cũ vào `bundles/before_collection_<run_id>.zip`, rồi thu
thập vào thư mục tạm. Chỉ output hoàn tất mới được chép vào acquisition; một
collector thất bại giữ nguyên output cũ của collector đó. Manifest được cập
nhật cho các file do lần thu thập này tạo ra, và dữ liệu ngoài output thay đổi
bất thường sẽ chặn cập nhật. Vì vậy cần chạy lại **1. Xử lý dữ liệu thô** sau
mỗi lần thu thập, rồi chạy **2. Chạy phân tích**. Nút **Tạo manifest + SHA-256**
và CLI `preserve` kiểm tra manifest đã có thay vì tự thay mốc hash.

Nếu Case từ bản cũ đã báo `mismatched` ở các JSON live, bản vá không khôi phục
được nội dung đã bị ghi đè. Giữ Case đó để đối chiếu; khôi phục file đúng hash
từ Evidence Bundle cũ nếu có, hoặc tạo Case mới và thu thập lại. Không thay
hash cũ chỉ để bỏ cảnh báo. Agent Mode cũng kiểm tra bằng chứng đã đăng ký
trước khi nhập thêm một bundle vào Case.

Khi cập nhật bản vá, đóng Crow-Eye và chép các file vào đúng thư mục dự án.
Bản vá bao gồm hộp thoại tiến trình cho xử lý dữ liệu thô, phân tích và thu thập.
Lệnh Hayabusa dùng `--no-wizard --no-color` để chạy từ giao diện mà không yêu
cầu terminal tương tác. Sau khi cập nhật, chạy lại **1. Xử lý dữ liệu thô** rồi
**2. Chạy phân tích** để bổ sung kết quả Hayabusa nếu lần trước tool này thất bại.
Parser hỗ trợ timestamp Hayabusa dạng `2026-10-07 16:25:43.932 +00:00`, kể cả
offset khác UTC, và giữ nguyên chuỗi nguồn trong attributes.
Parser EvtxECmd đọc các trường có tên trong `Payload.EventData.Data`; parser
Hayabusa đọc `Details`, `ExtraFieldInfo` và `AllFieldInfo` ở dạng text/JSON.
Các sự kiện 4624/4625 dùng tài khoản đích, IP nguồn và LogonType khi có dữ liệu;
SubjectUserName/UserId không được dùng thay tài khoản đích. JSON nguồn được
giữ trong attributes, còn tóm tắt EvtxECmd dùng mô tả dễ đọc.
Timeline có cột **Nguồn** để phân biệt Hayabusa và EvtxECmd. Một sự kiện có thể
được nhiều công cụ hoặc nhiều rule Hayabusa ghi nhận nên số dòng Timeline
không phải số lần đăng nhập. Hayabusa chạy với `--profile verbose` để giữ
RecordID và đường dẫn EVTX. Hai luật đăng nhập chỉ tính một lần khi khớp Case,
hostname, channel, file EVTX, Event ID, RecordID và timestamp ở độ chính xác
millisecond; các dòng nguồn vẫn được liên kết đầy đủ trong Alert. Khi thiếu
thông tin nhận diện, các dòng được giữ riêng, không gộp chỉ theo thời gian.
Sau khi cập nhật, chạy lại **1. Xử lý dữ liệu thô** rồi **2. Chạy phân tích** để
áp dụng parser và phép đếm mới vào dữ liệu đã thu thập.
Nếu dùng Agent trên máy khác, cập nhật `agent/local_buffer.py`,
`agent/task_executor.py` trên máy đó và khởi động lại Agent.

Phân tích dữ liệu Case và lưu kết quả tuân theo
`case.verify_hash_before_analysis` trong `config/settings.json` (mặc định `true`).
Thiếu manifest hoặc hash bằng chứng sai sẽ dừng phân tích. Dữ liệu chuẩn hóa
được liên kết bằng SHA-256 với manifest của lần xử lý tương ứng. Sau khi cập nhật
bản vá, hãy chạy lại **1. Xử lý dữ liệu thô** để tạo liên kết này cho Case cũ;
cũng cần xử lý lại sau mỗi lần thu thập mới. Overview hiển thị kết quả kiểm tra
SHA-256 gần nhất cùng thời điểm, không coi việc có manifest là đã verify.

Trong **Investigate → Baseline**, bấm **Lưu baseline T0** sau khi thu thập và
xử lý dữ liệu trước thử nghiệm. Mỗi lần lưu tạo một snapshot mới và Evidence
Bundle riêng, giữ bằng chứng T0 trong `bundles/` và dữ liệu đối chiếu trong
`analysis/baselines/`. Sau thử nghiệm, thu thập T1, xử lý dữ liệu thô rồi phân
tích để so với T0 mới nhất. Đối chiếu hỗ trợ trạng thái/cấu hình dịch vụ, hash
file đã thu, Registry và Scheduled Task khi có dữ liệu tương ứng. Đối tượng
không quan sát thấy ở T1 không tự chứng minh rằng nó đã bị xóa.

Trước khi chuyển Incident sang **Confirmed**, hoàn tất và lưu checklist trong
Investigate, nhập kết luận và chọn ít nhất một tác động CIA. Quyết định
False Positive/Not Confirmed không yêu cầu hoàn tất checklist.

Luật `service_stopped` với cấu hình mặc định yêu cầu bối cảnh rõ ràng không được
phê duyệt (`authorized=false`, `approved=false` hoặc `change_approved=false`)
và `downtime_seconds`/`outage_seconds` đạt ngưỡng. Event 7036 riêng lẻ vẫn có
thể tạo Finding để điều tra; không tự chứng minh gián đoạn trái phép. Dữ liệu
probe cần có đúng hostname/IP đích và service name/port để hỗ trợ tương quan.
Một snapshot kết nối đông chỉ tạo nghi vấn connection flood; đánh giá DoS và
Availability vẫn cần probe, baseline và bằng chứng thực nghiệm.

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m experiments.run_ground_truth
```

Số liệu Precision/Recall/F1 trên fixture tổng hợp được tính theo rule của từng
scenario (`metric_scope=rule_per_scenario`) và chỉ dùng để hồi quy. Đây không
phải độ chính xác theo từng alert/event hoặc trên VM thực. Chương thực nghiệm
luận văn phải đo lại trên VM lab với evidence thật và tập benign.

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
