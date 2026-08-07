# Synthetic test fixtures

Các fixture trong thư mục này chỉ dùng để kiểm thử tự động. Mọi hostname,
địa chỉ IP, tài khoản, command và timestamp đều là dữ liệu tổng hợp trong lab.

- `scenarios/`: record trung gian cho bốn kịch bản demo chính.
- `ground_truth/`: bốn kịch bản thực nghiệm có nhãn đúng kỳ vọng để đo
  rule-level TP/FP/FN, precision, recall và F1.
- `tool_outputs/`: CSV tổng hợp mô phỏng output có cấu trúc của công cụ DFIR.

Fixture không phải bằng chứng thu từ hệ thống thật và không được dùng để đưa ra
kết luận điều tra.
