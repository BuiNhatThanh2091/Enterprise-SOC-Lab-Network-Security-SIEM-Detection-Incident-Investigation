# A07 — Suspicious Data Staging or Raw Transfer

## 1. Detection ID
A07

## 2. Detection Name
Suspicious Data Staging or Raw Transfer (PowerShell ScriptBlock)

## 3. Detection Objective
Phát hiện hành vi chuẩn bị dữ liệu (Data Staging) thông qua lệnh nén tệp tin cục bộ hoặc hành vi mở socket mạng thô (`System.Net.Sockets.TcpClient`) để truyền dữ liệu bất thường ra ngoài biên mà không sử dụng các tiến trình web chuẩn, thông qua cơ chế giám sát PowerShell ScriptBlock Logging.

## 4. Security Context
Nằm ở giai đoạn **Collection & Exfiltration (Giai đoạn 5 - Thu thập và Trích xuất dữ liệu)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1560.001` (Archive via Utility) và `T1048.003` (Exfiltration Over Unencrypted Non-C2 Protocol).

## 5. Attack Behavior
Sau khi sao chép hồ sơ Firefox, kẻ tấn công thực thi khối lệnh PowerShell sử dụng lệnh `Compress-Archive` để nén thư mục thành `C:\Users\Public\firefox_profile.zip`, sau đó tiếp tục thực thi khối lệnh khởi tạo đối tượng `.NET` `System.Net.Sockets.TcpClient('203.0.113.25', 9999)` để đẩy luồng byte dữ liệu trực tiếp ra ngoài biên qua cổng `TCP/9999`.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Máy trạm Windows 10 Pro `10.10.35.18`).
* **Định dạng gốc**: Microsoft Windows PowerShell Operational Event ID 4104 (ScriptBlock Logging).
* **Giao thức truyền**: Windows Event Forwarding (WEC) / ArcSight Native Connector (Generator ID 2009).

## 7. Observable Evidence
Bản ghi giải mã khối lệnh PowerShell trong trường `message`:
* `externalId = 4104`
* Nhánh 1 (Staging): Chứa chuỗi `"Compress-Archive"` và `"\Users\Public\"`.
* Nhánh 2 (Raw Transfer): Chứa chuỗi `"TcpClient"` và `"GetStream"` (hoặc `"System.Net.Sockets.TcpClient"`).

## 8. Required Fields
* `deviceProduct`: Phải bằng `"PowerShell"`.
* `externalId`: Bằng `4104`.
* `message`: Chứa các từ khóa của Nhánh 1 hoặc Nhánh 2.
* `deviceHostName`: `"IT-ADMIN"`.

## 9. Detection Logic
Cấu trúc hai nhánh logic kết hợp `OR`:
* **Nhánh A (Data Staging)**: `externalId = 4104` AND `message CONTAINS "Compress-Archive"` AND `message CONTAINS "\Users\Public\"`.
* **Nhánh B (Raw Socket Transfer)**: `externalId = 4104` AND `message CONTAINS "TcpClient"` AND `message CONTAINS "GetStream"`.

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND externalId=4104 AND ((message CONTAINS "Compress-Archive" AND message CONTAINS "\Users\Public\") OR (message CONTAINS "TcpClient" AND message CONTAINS "GetStream"))
```

## 11. ESM Logic
```text
(External ID = 4104) AND 
(Device Product = PowerShell) AND 
(
    ((Message Contains Compress-Archive) AND (Message Contains \Users\Public\)) 
    OR 
    ((Message Contains System.Net.Sockets.TcpClient) AND (Message Contains GetStream))
)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng khối lệnh thực thi - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Rất Cao (High / Severity 8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A07 Suspicious Data Staging or Raw Transfer`
* Host: `IT-ADMIN` | Dạng phát hiện: Nén dữ liệu hoặc truyền raw socket.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình hai nhánh, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Quản trị viên sử dụng script PowerShell tự động để nén tệp sao lưu hoặc kiểm tra kết nối mạng qua socket (thường script quản trị hợp lệ chạy theo lịch trình cố định và không hướng tới thư mục `\Users\Public\`).

## 16. Investigation Pivot
Khi Rule A07 kích hoạt:
1. Đọc toàn văn khối lệnh trong trường `message` trên Logger để trích xuất địa chỉ IP và cổng đích (`203.0.113.25:9999`) cùng tên tệp nén (`firefox_profile.zip`).
2. Đối chiếu với log mạng của pfSense và Zeek trong cùng khung thời gian ($\Delta t \le 30\text{s}$) trên cổng `TCP/9999` để xác nhận số byte thực tế đã được gửi thành công ra ngoài.

## 17. Related Detection
* Trước đó: **A06** (Sao chép thư mục Firefox profile).
* Tiếp nối bởi: **A08** (Tải công cụ trung chuyển Ligolo-ng).

## 18. Limitations
Yêu cầu chính sách `Script Block Logging` (Event ID 4104) phải được bật trước trong Group Policy. Nếu kẻ tấn công sử dụng các kỹ thuật vô hiệu hóa logging (như can thiệp ETW patch hoặc AMSI bypass), bản ghi 4104 có thể bị chặn không sinh ra.

## 19. Public-Safe Representation
* Thư mục đích: `C:\Users\Public\`.
* Đích truyền dữ liệu: `203.0.113.25:9999`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 96, 97, 109, 118.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A07 trong ESM và Logger query 2 events ScriptBlock (Trang 97, 118).
