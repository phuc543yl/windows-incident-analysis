# Harmless sample evidence

Thư mục này chứa dữ liệu **tổng hợp** phục vụ integration test. Không file nào
là EVTX, Prefetch hoặc Registry Hive thật.

- `live/system.json`: snapshot host lab tối giản.
- `raw/EventLogs/Security.evtx.sample`: payload văn bản có marker rõ ràng.
- `raw/FirewallLogs/pfirewall.log`: log firewall tổng hợp dùng địa chỉ tài liệu.

Khi demo thật, hãy thay các file `.sample` bằng evidence thu từ máy ảo lab và
luôn tạo lại manifest SHA-256.
