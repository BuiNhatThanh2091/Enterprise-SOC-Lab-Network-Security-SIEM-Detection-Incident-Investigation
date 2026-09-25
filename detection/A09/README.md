# A09 — Suspicious External Tunnel

## 1. Detection ID
A09

## 2. Detection Name
Suspicious External Tunnel (Ligolo-ng Session)

## 3. Detection Objective
Phát hiện phiên hầm mạng chuyển tiếp dữ liệu ra ngoài (Protocol Tunneling) được thiết lập từ máy trạm nội bộ tới máy chủ tấn công ngoài biên thông qua cổng dịch vụ chuyên dụng `TCP/11601` của công cụ Ligolo-ng Proxy, dựa trên dữ liệu socket từ Sysmon Event ID 3 và Zeek `conn.log`.

## 4. Security Context
Nằm ở giai đoạn **Pivoting & Lateral Movement (Giai đoạn 6 - Thiết lập đường hầm trung chuyển)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1572` (Protocol Tunneling).

## 5. Attack Behavior
Sau khi tiến trình `agent.exe` được kích hoạt trên `IT-ADMIN01` (`10.10.35.18`), công cụ mở kết nối socket TCP hướng ngoại tới máy chủ Ligolo Proxy trên Kali (`203.0.113.25:11601`). Kết nối này tạo ra một đường hầm ảo TUN cho phép kẻ tấn công định tuyến ngầm các gói tin trực tiếp từ Kali vào các dải mạng DMZ và Internal.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Sysmon Event ID 3) và `ZEEK-NDR01` (`conn.log`).
* **Định dạng gốc**: Sysmon XML NetworkConnect và Zeek TSV.
* **Giao thức truyền**: WEC API (Sysmon) và Syslog UDP 5518 (Zeek).

## 7. Observable Evidence
* `externalId = 3` (Sysmon Event ID 3).
* `destinationProcessName` tương ứng với `agent.exe`.
* `sourceAddress = 10.10.35.18`.
* `destinationAddress = 203.0.113.25`.
* `destinationPort = 11601`.
* `transportProtocol = "TCP"`.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Sysmon"` (hoặc `"Zeek"` trên kênh mạng).
* `externalId`: Bằng `3`.
* `sourceAddress`: Thuộc mạng nội bộ (`InSubnet 10.10.35.0/24`).
* `destinationAddress`: Thuộc mạng ngoài biên (`InSubnet 203.0.113.0/24`).
* `destinationPort`: Bằng `11601`.

## 9. Detection Logic
Khớp khi một kết nối mạng hướng ngoại được tạo từ dải máy trạm nội bộ tới địa chỉ ngoài biên trên cổng đích 11601.

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND deviceProduct="Sysmon" AND externalId=3 AND sourceAddress=10.10.35.18 AND destinationAddress=203.0.113.25 AND destinationPort=11601
```

## 11. ESM Logic
```text
(External ID = 3) AND 
(Transport Protocol = TCP) AND 
(Device Product = Sysmon) AND 
(Source Address InSubnet 10.10.35.0/24) AND 
(Target Address InSubnet 203.0.113.0/24) AND 
(Target Port = 11601)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện kết nối socket - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Rất Cao (High / Severity 8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A09 Suspicious External Tunnel (Ligolo Session)`
* Nguồn: `10.10.35.18` | Đích: `203.0.113.25:11601` | Cổng: `11601`.

## 14. Validation Status
**OBSERVED FIRING — SCENARIO-DEPENDENT** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Hầu như không có kết nối doanh nghiệp hợp lệ nào sử dụng cổng đích 11601 ra ngoài Internet trừ khi tổ chức có ứng dụng chuyên dụng trùng cổng.

## 16. Investigation Pivot
Khi Rule A09 kích hoạt:
1. Xác nhận trạm trung chuyển (Pivot Host) đã được hình thành thành công tại `10.10.35.18`.
2. Theo dõi ngay lập tức các luồng kết nối liên vùng xuất phát từ hoặc đi qua máy trạm này tới các máy chủ trong DMZ (`WEB01`) hoặc Internal (`DB01`).
3. Chuẩn bị đối soát với cảnh báo kết nối SSH (`A10`) trên tuyến Security Transit.

## 17. Related Detection
* Trước đó: **A08** (Tải và thực thi nhị phân `agent.exe`).
* Tiếp nối bởi: **A10** (Phiên SSH chuyển dịch ngang vào máy chủ Web DMZ).

## 18. Limitations
Rule này là **Scenario-Dependent** vì phụ thuộc vào cổng mặc định của Ligolo-ng (`TCP/11601`). Nếu kẻ tấn công thay đổi cổng lắng nghe của proxy server trên Kali sang cổng 443 hoặc 80, rule này sẽ không phát hiện được theo điều kiện cổng.

## 19. Public-Safe Representation
* Trạm trung chuyển: `10.10.35.18` (IT-ADMIN01).
* Máy chủ hầm ngầm: `203.0.113.25:11601`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 98, 99, 110, 119, 120.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A09 trong ESM và Logger query bản ghi Sysmon Event 3 (Trang 99, 120).
