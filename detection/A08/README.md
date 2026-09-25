# A08 — Suspicious Tool Transfer or Execution

## 1. Detection ID
A08

## 2. Detection Name
Suspicious Tool Transfer or Execution (Ligolo-ng Agent)

## 3. Detection Objective
Nhận diện hành vi tải về hoặc kích hoạt thực thi công cụ đường hầm chuyển tiếp mạng (Ligolo-ng client binary) tại máy trạm, thông qua sự phối hợp giữa giám sát khối lệnh tải tệp của PowerShell và kiểm toán tạo tiến trình của Sysmon.

## 4. Security Context
Nằm ở giai đoạn **Pivoting & Tool Ingress (Giai đoạn 6 - Chuẩn bị trung chuyển mạng)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1105` (Ingress Tool Transfer) và `T1572` (Protocol Tunneling).

## 5. Attack Behavior
Để mở rộng phạm vi tiếp cận từ máy trạm vào vùng DMZ và nội bộ mà không bị rào cản firewall biên ngăn chặn, kẻ tấn công thực thi lệnh `Invoke-WebRequest` tải nhị phân `agent.exe` từ máy Kali (`203.0.113.25:8080`) về `C:\Users\Public\agent.exe`, sau đó thực thi tiến trình này với các tham số kết nối `-connect 203.0.113.25:11601 -ignore-cert`.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Máy trạm Windows 10 Pro `10.10.35.18`).
* **Định dạng gốc**: PowerShell Event ID 4104 (nhánh tải tệp) và Sysmon Event ID 1 (nhánh thực thi tiến trình).
* **Giao thức truyền**: Windows Event Forwarding (WEC) / ArcSight Native Connector (Generator ID 2009).

## 7. Observable Evidence
* **Nhánh tải tệp (PowerShell 4104)**: `message` chứa `"Invoke-WebRequest"`, `"-OutFile"`, và `"ligolo-agent.exe"` (hoặc `.exe`).
* **Nhánh thực thi (Sysmon 1)**: `destinationProcessName CONTAINS "agent.exe"` và `deviceCustomString4` chứa tham số `"-connect"` hoặc `"-ignore-cert"`.

## 8. Required Fields
* Nhánh PowerShell: `externalId = 4104`, `deviceProduct = "PowerShell"`, `message`.
* Nhánh Sysmon: `externalId = 1`, `deviceProduct = "Sysmon"`, `destinationProcessName`, `deviceCustomString4`.
* `deviceHostName`: `"IT-ADMIN"`.

## 9. Detection Logic
Cấu trúc phát hiện hợp nhất hai hành vi:
* **Nhánh A (Tải công cụ)**: PowerShell tải tệp thực thi qua lệnh `Invoke-WebRequest` hướng tới thư mục `\Users\Public\`.
* **Nhánh B (Thực thi công cụ)**: Tiến trình `agent.exe` được gọi chạy với các cờ tham số đặc trưng của Ligolo-ng client (`-connect`, `-ignore-cert`).

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND ((externalId=4104 AND message CONTAINS "Invoke-WebRequest" AND message CONTAINS "ligolo-agent.exe") OR (deviceProduct="Sysmon" AND externalId=1 AND destinationProcessName CONTAINS "agent.exe"))
```

## 11. ESM Logic
```text
(
    (External ID = 4104) AND (Device Product = PowerShell) AND 
    (Message Contains Invoke-WebRequest) AND (Message Contains -OutFile) AND (Message Contains .exe)
) 
OR 
(
    (External ID = 1) AND (Device Product = Sysmon) AND 
    ((Device Custom String 4 Contains -connect) OR (Device Custom String 4 Contains -ignore-cert))
)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Cao (High / Severity 7–8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A08 Suspicious Tool Transfer or Execution`
* Host: `IT-ADMIN` | Dạng phát hiện: Tải công cụ hoặc chạy `agent.exe`.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình hai nhánh, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Người dùng tải các tệp cập nhật phần mềm hợp lệ bằng PowerShell hoặc chạy các phần mềm giám sát mạng nội bộ có tên `agent.exe` (tuy nhiên tham số `-connect` kèm `-ignore-cert` là rất đặc thù cho công cụ kiểm thử).

## 16. Investigation Pivot
Khi Rule A08 kích hoạt:
1. Trích xuất địa chỉ IP máy chủ điều khiển Ligolo (`203.0.113.25`) và cổng kết nối (`11601`).
2. Chuyển sang giám sát mạng (Zeek `conn.log` hoặc Sysmon Event ID 3) để theo dõi sự hình thành của phiên hầm ngầm (`A09`).
3. Chuẩn bị biện pháp cô lập máy trạm để ngăn chặn việc chuyển dịch ngang qua đường hầm ảo.

## 17. Related Detection
* Trước đó: **A07** (Trích xuất hồ sơ trình duyệt ra ngoài).
* Tiếp nối bởi: **A09** (Thiết lập phiên đường hầm Ligolo-ng).

## 18. Limitations
Nếu kẻ tấn công đổi tên tệp thực thi (không dùng `agent.exe`) và sử dụng các phương thức tải tệp khác (chẳng hạn qua certutil, bitsadmin, hoặc tải qua kết nối reverse shell có sẵn), nhánh Sysmon có thể không bắt được nếu không khớp tên tiến trình.

## 19. Public-Safe Representation
* Máy trạm: `IT-ADMIN` (`10.10.35.18`).
* Đường dẫn công cụ: `C:\Users\Public\agent.exe`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 97, 98, 109, 119.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A08 trong ESM và Logger query kết quả tải/thực thi tiến trình (Trang 98, 119).
