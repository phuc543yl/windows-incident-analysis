# Crow-Eye Sample Test

Gói dữ liệu mô phỏng để chạy thử nhanh trên Crow-Eye, không cần bật VM Windows 8.
Script không kết nối mạng, không brute force, không chạy PowerShell, không tạo Scheduled Task hoặc Service trên hệ điều hành. Các lệnh trong JSON chỉ là chuỗi dữ liệu cho rule đọc.

## Phiên bản

Dùng với https://github.com/phuc543yl/windows-incident-analysis tại commit 9861df66fb81dd41103e864c5634133449154184.
Gói không phải toàn bộ dự án; chạy bằng môi trường Python đang dùng cho tool của bạn.
Bản crow-eye-windows-incident-analysis có các rule khác. Script sẽ dừng trước khi tạo Case nếu thiếu rule bắt buộc. Script không tự sửa luật/cấu hình để đạt PASS.

## Cách chạy nhanh

1. Giải nén. Đặt thư mục CrowEye_Sample_Test cùng cấp với main.py của dự án.
2. Mở PowerShell tại thư mục dự án, kích hoạt môi trường Python bạn dùng để chạy tool.
3. Chạy:

```powershell
python .\CrowEye_Sample_Test\run_sample.py --root .
```

Ví dụ nếu thư mục dự án của bạn vẫn là D:\tool\tool\tool:

```powershell
cd D:\tool\tool\tool
python .\CrowEye_Sample_Test\run_sample.py --root .
```

Hoặc chạy RUN_SAMPLE.bat trong thư mục gói. Batch ưu tiên .venv\Scripts\python.exe ở thư mục dự án nếu có, nếu không dùng python trong PATH.

Mỗi lần chạy tạo HAI CASE MỚI có nhãn [SYNTHETIC], không ghi đè Case cũ. Đóng giao diện trong lúc tạo để tránh danh sách Case chưa được làm mới.

## Kết quả kỳ vọng

| Case | Records | Alerts | Incidents |
|---|---:|---:|---:|
| [SYNTHETIC] Full incident chain | 122 | 8 | 3 |
| [SYNTHETIC] Normal control | 11 | 0 | 0 |

Case ID phụ thuộc ngày và số Case sẵn có. Sử dụng ID in ra từ lần chạy của bạn, không nhập một ID ví dụ cố định.

Case full gồm sáu đăng nhập thất bại, một thành công Type 10, PowerShell mã hóa, tạo Task, đăng ký Service, file khác hash, 110 quan sát kết nối và một probe timeout mô phỏng.

Tám rule kỳ vọng:
- failed_logon_burst
- successful_logon_after_failures
- suspicious_powershell
- scheduled_task_created
- service_configuration_changed
- file_integrity_change
- connection_flood
- service_probe_failed

Ba loại incident: account_compromise, endpoint_compromise, dos_attack. Chúng phải còn suspected và chưa có CIA được chuyên viên xác nhận.

Case normal gồm bốn đăng nhập thất bại dưới ngưỡng, PowerShell Get-Date, file có hash không đổi và năm kết nối. Các record này được xử lý riêng để tránh cộng chung với ca full.

## Xem trên giao diện

1. Chạy python main.py bằng cách bạn thường mở tool.
2. Tab Case: làm mới danh sách nếu có, chọn đúng Case ID được script in ra và mở Case. Nếu danh sách chưa cập nhật, khởi động lại giao diện.
3. Analysis: kết quả đã được script tạo bằng AnalysisService của tool. Làm mới kết quả hoặc bấm “2. Chạy phân tích” để chạy lại rule.
4. KHÔNG bấm “1. Xử lý dữ liệu thô” hoặc thu thập Local/Agent trên hai Case này: gói dùng ProcessingPipeline với JSON mô phỏng, không có EVTX để parser bên ngoài đọc. Xử lý raw có thể thay thế tập record mẫu. Nếu đã bấm nhầm, chạy lại script để tạo Case mẫu mới.
5. Evidence: manifest đã có; bấm “Kiểm tra toàn vẹn”. Đó là hash của fixture, không chứng minh nguồn Windows thật. Không cần tạo lại manifest.
6. Timeline: xóa lọc; xem 4625,4624 rồi 4698,7045; bỏ lọc Event ID để thấy process/network/file. Thời gian UTC được dịch về gần thời điểm chạy và in trên terminal. IP mẫu 192.0.2.10; host WIN8-DEMO; user labuser.
7. Investigate → Pivot: thử ip=192.0.2.10 hoặc process=powershell.exe. Baseline: Case full có cặp tracked khác hash; Case normal có hai bản giống nhau. Có thể thấy hai dòng sai khác (từ record và cặp file); không tính thành hai lần thay đổi thực tế.
8. Incidents: kiểm tra suspected, các alert liên kết và details. Chỉ nhập kết luận diễn tập với nhãn dữ liệu tổng hợp; không kết luận có máy Windows bị xâm nhập thật.
9. Report: xuất bằng chức năng có sẵn của tool, giữ nhãn [SYNTHETIC]. Phần xuất báo cáo phụ thuộc các thư viện của môi trường bạn cài.

## Muốn tự bấm chạy phân tích

Chỉ tạo bằng chứng mẫu và record/timeline, chưa chạy Analysis:

```powershell
python .\CrowEye_Sample_Test\run_sample.py --root . --prepare-only
```

Sau đó mở Case được in ra và bấm “2. Chạy phân tích”. Trạng thái PREPARED nghĩa là mới chuẩn bị, không phải PASS của detection.

Chỉ tạo một Case:

```powershell
python .\CrowEye_Sample_Test\run_sample.py --root . --scenario full
python .\CrowEye_Sample_Test\run_sample.py --root . --scenario normal
```

Có thể đặt gói ngoài dự án và truyền --root "D:\duong-dan-du-an".

## File được tạo

Dưới runtime/cases/CASE-ID mới:
- acquisition/raw/Files/fixture_records.json: dữ liệu đầu vào có nhãn synthetic.
- acquisition/raw/Files/tracked_before.txt và tracked_after.txt: file mẫu.
- acquisition/raw/Files/SYNTHETIC_NOTICE.txt: ghi rõ nguồn mô phỏng.
- Manifest, hash, normalized records, timeline, kết quả analysis do các service của dự án tạo.
- sample_test_result.json: kỳ vọng, thực tế và các phép đối chiếu PASS/FAIL.
- sample_test_error.json: thông tin lỗi nếu tạo Case chưa hoàn tất.

Không cần và không nên sửa file normalized hoặc alert bằng tay để ép PASS.

## Đọc kết quả

PASS: số record/timeline đúng; nguồn tham chiếu tồn tại; Baseline đúng; tập rule, số alert, loại/số incident khớp; incident còn suspected và không tự xác nhận CIA; liên kết record hợp lệ.
FAIL: mở sample_test_result.json, xem mục checks và rule thực tế. Kiểm tra lại phiên bản/cấu hình trước khi sửa dữ liệu.
ERROR: sai đường dẫn, thiếu module, lỗi môi trường hoặc phiên bản không phù hợp. Script trả mã 2; nếu đã tạo một Case thì giữ lại để chẩn đoán và in đường dẫn.

Không có main.py: bạn đang đứng sai thư mục dự án. Missing enabled rules: kiểm tra git remote -v và git rev-parse HEAD; gói hướng tới repository/commit đã ghi ở trên.

## Giới hạn của phép thử

Đã kiểm tra pipeline và engine bằng Python trong môi trường Linux với các module của commit đã ghi. Chưa kiểm tra giao diện Windows hoặc parser EVTX trên máy bạn.

Gói kiểm thử logic chuẩn hóa, detection, correlation, lưu kết quả và so file. Nó không kiểm chứng thu thập Agent, parser EVTX, hiệu quả phát hiện trên dữ liệu thực, DoS thực, hay rò rỉ dữ liệu. Probe timeout và hash-change record ở đây được chủ động tạo cho fixture; chúng không phải số đo từ endpoint.

Để kiểm thử thu thập Windows thực, dùng bộ test case lab đã soạn trước. Không đưa kết quả mẫu này vào Chương 3 dưới nhãn thực nghiệm Windows thật.
