# Kịch bản demo phân tích sự cố Windows

## 1. Mục tiêu demo

Bốn kịch bản chứng minh công cụ hỗ trợ quy trình phân tích sự cố thay vì chỉ
phát hiện một event:

1. tiếp nhận giả thuyết và tạo Case;
2. thu thập/chọn evidence phù hợp;
3. chuẩn hóa và dựng timeline;
4. chạy detection rule;
5. correlation thành incident nghi vấn;
6. chuyên viên xác minh tác động CIA và xuất báo cáo.

Mặc định nên dùng fixture tổng hợp trong `tests/fixtures/scenarios/`. Khi cần
demo thu thập thật, chỉ thực hiện trên máy ảo lab được phép, có snapshot và dữ
liệu giả. Không dùng tài khoản, IP hoặc artifact của hệ thống thật.

## 2. Ma trận kịch bản

| Scenario ID | Profile | Dấu hiệu chính | Incident | CIA khi xác nhận |
|---|---|---|---|---|
| `account_compromise` | `account_compromise` | Nhiều 4625 rồi 4624 RDP cùng user/IP | `account_compromise` | Confidentiality, Integrity |
| `endpoint_compromise` | `endpoint_compromise` | PowerShell mã hóa, Run Key, Scheduled Task, Prefetch | `endpoint_compromise` | Integrity |
| `log_tampering` | `log_tampering` | Security Event ID 1102 | `log_tampering` | Integrity |
| `service_disruption` | `service_disruption` | Service 7036 stopped và 7040 disabled | `service_disruption` | Availability |

Tác động CIA trong bảng là kết quả kỳ vọng của bài demo sau khi chuyên viên
xác nhận, không được tự động gán chỉ từ Event ID.

## 3. Quy trình demo chung

### 3.1. Chuẩn bị

- Kích hoạt `.venv` và cài `requirements.txt`.
- Xác nhận cấu hình JSON bằng unit test.
- Nếu dùng tool thật, đặt executable dưới `tools/` và chạy `ToolValidator`.
- Nếu dùng Agent, đặt token bằng biến môi trường và kiểm tra `/api/v1/health`.
- Khôi phục snapshot sạch trước mỗi kịch bản thật.

### 3.2. Chạy fixture tự động

```powershell
pytest tests\integration\test_scenario_workflows.py -q
```

Test tạo Case tạm, đưa record tổng hợp qua `ProcessingPipeline`, chạy
`AnalysisService`, kiểm tra rule/incident mong đợi, rồi mô phỏng quyết định của
chuyên viên để xác nhận CIA. Fixture không chạy tấn công mạng hoặc thay đổi máy
thật.

### 3.3. Trình bày trên giao diện

1. Mở tab Case và tạo Case theo đúng profile.
2. Nêu giả thuyết trước khi xem alert.
3. Mở Evidence để chỉ ra nguồn và SHA-256.
4. Mở Timeline để kể lại thứ tự sự kiện.
5. Mở Analysis để phân biệt finding, alert và incident.
6. Giữ incident ở `suspected` trong lúc đối chiếu.
7. Nhập kết luận, đổi status và chọn CIA impact.
8. Xuất báo cáo HTML/PDF và bundle nếu cần bàn giao.

## 4. Kịch bản 1: Account compromise qua RDP

### 4.1. Giả thuyết

Tài khoản `labuser` bị thử mật khẩu nhiều lần từ một địa chỉ nguồn, sau đó có
đăng nhập RDP thành công và có nguy cơ bị truy cập/tráo đổi dữ liệu.

### 4.2. Evidence tối thiểu

- Security Event Log;
- Event ID 4625: đăng nhập thất bại;
- Event ID 4624 với Logon Type 10: RDP thành công;
- `TargetUserName`, `IpAddress`, hostname và timestamp.

Firewall log là nguồn bổ sung, không thay thế Security Log.

### 4.3. Chuỗi fixture

```text
08:00-08:04Z  5 lần 4625, user labuser, IP 203.0.113.10, LogonType 10
08:05Z        1 lần 4624, cùng user/IP và LogonType
```

### 4.4. Kết quả kỳ vọng

- Rule `failed_logon_burst`;
- rule `successful_logon_after_failures`;
- correlation `account_compromise`;
- incident ban đầu `suspected`, chưa có CIA;
- sau đối chiếu: `confirmed`, CIA gồm `confidentiality` và `integrity`.

Chuyên viên cần loại trừ quên mật khẩu, scanner nội bộ, jump host hợp lệ và
việc 4624 thuộc một phiên không liên quan trước khi xác nhận.

## 5. Kịch bản 2: Endpoint compromise và persistence

### 5.1. Giả thuyết

PowerShell đáng ngờ đã chạy payload thử nghiệm, sau đó tạo Run Key hoặc
Scheduled Task để duy trì thực thi.

### 5.2. Evidence tối thiểu

- process snapshot hoặc Event ID 4688/Sysmon tương đương;
- command line PowerShell;
- Registry Run Key;
- Scheduled Task XML hoặc Event ID 4698;
- Prefetch/Amcache và file metadata nếu có.

### 5.3. Chuỗi fixture

```text
09:00Z  powershell.exe có -EncodedCommand
09:02Z  HKCU/.../Run/LabUpdater trỏ tới file lab
09:03Z  Scheduled Task LabUpdater gọi PowerShell
09:04Z  Prefetch xác nhận LAB-PAYLOAD.EXE đã chạy
```

### 5.4. Kết quả kỳ vọng

- `suspicious_powershell`;
- `registry_autorun_change`;
- `scheduled_task_created`;
- `suspicious_file_execution`;
- incident `endpoint_compromise`;
- sau khi chuyên viên chứng minh thay đổi trái phép: CIA `integrity`.

Encoded PowerShell không tự động là độc hại. Chuyên viên phải kiểm tra parent
process, user, chữ ký/hash file, đường dẫn, nội dung giải mã và phần mềm quản
trị hợp lệ.

## 6. Kịch bản 3: Log tampering

### 6.1. Giả thuyết

Security Log bị xóa nhằm che giấu hoạt động trước đó, làm mất tính toàn vẹn của
dấu vết kiểm toán.

### 6.2. Evidence tối thiểu

- Security Event ID 1102;
- user thực hiện, timestamp, hostname;
- log Agent/audit và evidence lân cận nếu có;
- bản sao EVTX/hash được thu sớm nhất có thể.

### 6.3. Kết quả kỳ vọng

- rule `security_log_cleared`;
- incident `log_tampering`;
- sau khi loại trừ bảo trì được phê duyệt: CIA `integrity`.

Một event 1102 trong lịch bảo trì hợp lệ có thể là benign true positive hoặc
`not_confirmed`; rule vẫn đúng về mặt phát hiện hành vi.

## 7. Kịch bản 4: Service disruption

### 7.1. Giả thuyết

Dịch vụ thử nghiệm `CrowEyeLabService` bị dừng và chuyển startup type thành
disabled trái phép, gây mất khả dụng của chức năng lab.

### 7.2. Evidence tối thiểu

- System Event ID 7036 cho trạng thái stopped;
- System Event ID 7040 cho thay đổi startup type;
- process/user thực hiện nếu log có;
- snapshot service và Registry service key.

### 7.3. Chuỗi fixture

```text
11:00Z  CrowEyeLabService chuyển sang stopped
11:01Z  startup type chuyển sang disabled
```

### 7.4. Kết quả kỳ vọng

- rule `service_stopped`;
- rule `service_configuration_changed`;
- incident `service_disruption`;
- sau khi chứng minh chức năng bị gián đoạn: CIA `availability`.

Không dùng dịch vụ hệ thống quan trọng để demo. Dịch vụ dừng do update, bảo
trì hoặc thao tác được phê duyệt phải được đánh dấu phù hợp sau xác minh.

## 8. Tiêu chí pass/fail

Một kịch bản **pass** khi:

- số record sau normalization đúng với input sau khi loại trùng;
- timeline chứa mọi record cần cho giả thuyết;
- tập rule kỳ vọng là tập con của alert thực tế;
- correlation tạo đúng `incident_type`;
- incident tự động vẫn là `suspected` và CIA rỗng;
- thao tác chuyên viên cập nhật đúng status, kết luận và CIA;
- báo cáo truy ngược được về record/evidence ID.

Kịch bản **fail** nếu chỉ có alert nhưng không truy được nguồn, hash không
khớp, correlation sai thực thể/thời gian, hoặc hệ thống tự tuyên bố
`confirmed` khi chưa có quyết định của chuyên viên.

## 9. Dọn dẹp sau demo

- Xuất báo cáo và bundle cần giữ.
- Đóng Case sau khi kết luận.
- Dừng Agent để giải phóng thread và file handle.
- Khôi phục snapshot VM nếu đã tạo thay đổi lab.
- Không đưa token, binary DFIR, EVTX thật hoặc dữ liệu định danh vào Git.
