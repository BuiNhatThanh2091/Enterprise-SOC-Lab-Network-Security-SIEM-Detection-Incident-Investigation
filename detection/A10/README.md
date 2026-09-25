# A10 — Internal Remote Access to WEB Tier

## 1. Detection ID
A10

## 2. Detection Name
Internal Remote Access to WEB Tier (SSH to DMZ)

## 3. Detection Objective
Ghi nhận phiên kết nối quản trị từ xa qua SSH (`TCP/22`) từ máy trạm nội bộ sang máy chủ web trong phân vùng DMZ được phép đi qua chốt chặn Suricata IPS. Rule này cung cấp bằng chứng ngữ cảnh về hành vi chuyển dịch ngang (Lateral Movement) sang phân vùng DMZ, không coi bản thân giao thức SSH là độc hại.

## 4. Security Context
Nằm ở giai đoạn **Pivoting & Lateral Movement (Giai đoạn 6 - Chuyển dịch ngang sang DMZ)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1021.004` (Remote Services: SSH).

## 5. Attack Behavior
Lợi dụng mật khẩu của tài khoản quản trị Linux `thanh` (đã giải mã từ profile Firefox ở giai đoạn trước) và tuyến định tuyến ảo qua đường hầm Ligolo-ng, kẻ tấn công khởi tạo phiên kết nối SSH trực tiếp từ máy tấn công xuyên qua đường hầm tới máy chủ `WEB01` (`10.10.34.13:22`). Dưới góc nhìn mạng, Suricata ghi nhận phiên SSH này xuất phát từ máy trạm trung gian `10.10.35.18`.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `SURICATA-IPS01` (trên tuyến Security Transit) kết hợp Linux `/var/log/auth.log` trên `WEB01`.
* **Định dạng gốc**: Suricata EVE JSON (`event_type: alert` hoặc `flow`).
* **Giao thức truyền**: Syslog TCP cổng `5521` (Generator ID 2002).

## 7. Observable Evidence
* `deviceProduct = "Suricata IDS IPS"`.
* `sourceAddress = 10.10.35.18` (Internal Subnet).
* `destinationAddress = 10.10.34.13` (DMZ Subnet).
* `destinationPort = 22`.
* `deviceAction = "allowed"`.
* `alert.signature = "SOCLAB BASELINE SSH Administration to WEB01"`.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Suricata IDS IPS"`.
* `deviceAction`: Bằng `"allowed"`.
* `sourceAddress`: Thuộc mạng nội bộ (`InSubnet 10.10.35.0/24`).
* `destinationAddress`: Thuộc mạng DMZ (`InSubnet 10.10.34.0/24`).
* `destinationPort`: Bằng `22`.

## 9. Detection Logic
Khớp khi Suricata ghi nhận một luồng kết nối SSH (port 22) được chấp thuận chuyển tiếp từ dải mạng nội bộ `10.10.35.0/24` sang dải mạng DMZ `10.10.34.0/24`.

## 10. Logger Validation Query
```text
deviceProduct="Suricata IDS IPS" AND sourceAddress=10.10.35.18 AND destinationAddress=10.10.34.13 AND destinationPort=22
```

## 11. ESM Logic
```text
(Device Action = allowed) AND 
(Device Product = Suricata IDS IPS) AND 
(Source Address InSubnet 10.10.35.0/24) AND 
(Target Address InSubnet 10.10.34.0/24) AND 
(Target Port = 22)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng phiên kết nối SSH - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Thông tin / Thấp (Severity 3) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A10 Internal Remote Access to WEB Tier`
* Nguồn: `10.10.35.18` | Đích: `10.10.34.13:22` | Trạng thái: `allowed`.

## 14. Validation Status
**OBSERVED FIRING — CONTEXTUAL / LATERAL MOVEMENT** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Các phiên kết nối SSH quản trị thông thường của kỹ sư IT từ trạm `IT-ADMIN01` vào `WEB01` phục vụ bảo trì hệ thống.

## 16. Investigation Pivot
Khi Rule A10 kích hoạt:
1. Đối soát chéo với nhật ký xác thực `/var/log/auth.log` trên máy chủ `WEB01` để xem phiên SSH sử dụng tài khoản nào (`thanh`) và đăng nhập thành công hay thất bại.
2. Kiểm tra các cảnh báo trước đó trên máy trạm nguồn `10.10.35.18` (như `A06`, `A07`, `A08`, `A09`) để xác định xem phiên SSH này là quản trị hợp lệ hay hành vi chuyển dịch ngang của kẻ tấn công.
3. Chuyển sang theo dõi các lệnh thực thi nhạy cảm trên máy chủ Web (`A11`).

## 17. Related Detection
* Trước đó: **A09** (Đường hầm Ligolo-ng tạo tuyến định tuyến ngầm).
* Tiếp nối bởi: **A11** (Thực thi lệnh đặc quyền trên Web để lấy mật khẩu DB).

## 18. Limitations
Rule này bắt luồng kết nối SSH dựa trên chính sách phân vùng mạng. Do giao thức SSH được mã hóa toàn bộ payload, Suricata **hoàn toàn không thể đọc được nội dung các câu lệnh được gõ trong phiên SSH**. Mọi giám sát hành vi bên trong phiên buộc phải dựa vào Linux Auditd trên máy chủ `WEB01`.

## 19. Public-Safe Representation
* Trạm nguồn: `10.10.35.18` (IT-ADMIN01).
* Máy chủ đích: `10.10.34.13` (WEB01 DMZ).

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 78, 99, 100, 110, 120, 121.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A10 trong ESM và Logger query 22 events SSH (Trang 100, 121).
