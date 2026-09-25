# A03 — Suspicious Script Execution

## 1. Detection ID
A03

## 2. Detection Name
Suspicious Script Execution (HTA via mshta.exe)

## 3. Detection Objective
Phát hiện hành vi thực thi mã độc tại điểm cuối thông qua việc lạm dụng tiến trình hợp lệ của hệ điều hành Windows (`mshta.exe` - Microsoft HTML Application Host) để khởi chạy tệp tin ứng dụng HTML (`.hta`) độc hại.

## 4. Security Context
Nằm ở giai đoạn **Exploitation & Execution (Giai đoạn 2 - Khai thác và Thực thi)** trong mô hình Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1218.005` (System Binary Proxy Execution: Mshta) và `T1059.001` (PowerShell).

## 5. Attack Behavior
Sau khi giải nén tệp `SecurityPatch_KB504991.zip`, nạn nhân trên trạm `IT-ADMIN01` (`10.10.35.18`) nhấp đúp vào tệp `SecurityPatch_KB504991.hta`. Hệ điều hành gọi tiến trình `mshta.exe`, từ đó khởi tạo shell trung gian `cmd.exe /c` để chạy ngầm `powershell.exe` với các tham số `-ExecutionPolicy Bypass -WindowStyle Hidden` nhằm nạp mã độc vào bộ nhớ.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Máy trạm Windows 10 Pro `10.10.35.18`).
* **Định dạng gốc**: Microsoft Sysmon Event ID 1 (Process Create) định dạng XML.
* **Giao thức truyền**: Windows Event Forwarding (WEC) / ArcSight Native Connector (Generator ID 2009).

## 7. Observable Evidence
Bản ghi kiểm toán tiến trình điểm cuối:
* `externalId = 1` (Sysmon Event ID 1).
* `destinationProcessName = "C:\Windows\System32\mshta.exe"` (hoặc `targetProcessName CONTAINS "mshta.exe"`).
* `deviceCustomString4 = "...SecurityPatch_KB504991.hta"` (`cs4Label="CommandLine"`).
* `deviceCustomString5 = "{ecec360d-d71c-6aab-3400-000000...}"` (`cs5Label="ProcessGuid"`).
* `sourceProcessName = "C:\Windows\explorer.exe"`.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Sysmon"`.
* `externalId`: Bằng `1`.
* `destinationProcessName`: Chứa `"mshta.exe"`.
* `deviceCustomString4`: Chứa `".hta"`.
* `deviceHostName`: Định danh máy trạm (`"IT-ADMIN"`).

## 9. Detection Logic
Khớp khi tiến trình tạo mới trên máy trạm là `mshta.exe` và dòng lệnh thực thi có chứa tham số tham chiếu tới tệp có phần mở rộng `.hta`.

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND deviceProduct="Sysmon" AND externalId=1 AND destinationProcessName CONTAINS "mshta.exe" AND deviceCustomString4 CONTAINS ".hta"
```

## 11. ESM Logic
```text
(External ID = 1) AND 
(Device Product = Sysmon) AND 
(Target Process Name Contains mshta.exe) AND 
(Device Custom String 4 Contains .hta)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện khởi tạo tiến trình đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Cao (High / Severity 7–8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A03 Suspicious Script Execution`
* Máy trạm: `IT-ADMIN` | Tiến trình: `mshta.exe` | Tham số: `.hta`.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế trong chuỗi tấn công).

## 15. False Positives / Benign Cases
Các ứng dụng doanh nghiệp cũ hoặc trình cài đặt phần mềm sử dụng giao diện HTA hợp lệ (hiếm gặp trong môi trường hiện đại nhưng có thể tồn tại trong các hệ thống legacy).

## 16. Investigation Pivot
Khi Rule A03 kích hoạt:
1. Trích xuất mã định danh duy nhất của tiến trình `ProcessGuid` (`deviceCustomString5`).
2. Truy vấn Sysmon Event ID 1 trên Logger với điều kiện `ParentProcessGuid = [ProcessGuid của mshta.exe]` để tìm các tiến trình con được sinh ra (`cmd.exe`, `powershell.exe`).
3. Truy vấn Sysmon Event ID 3 (Network Connect) với cùng `ProcessGuid` hoặc `ProcessGuid` của tiến trình con để xác định địa chỉ IP và cổng kết nối mạng hướng ngoại (`A04`).

## 17. Related Detection
* Trước đó: **A02** (Tải tệp nén chứa HTA).
* Tiếp nối bởi: **A04** (Kết nối ngược C2 trên cổng 4444).
* Hợp thành: **C01** (Mắt xích thứ hai trong bộ ba tương quan Initial Compromise).

## 18. Limitations
Rule được xây dựng cụ thể cho kỹ thuật thực thi HTA qua `mshta.exe`. Nếu kẻ tấn công sử dụng các công cụ Living off the Land (LotL) khác (như `rundll32.exe`, `regsvr32.exe`, `certutil.exe`) để kích hoạt mã độc, Rule A03 sẽ không bắt được mà cần các rule chuyên biệt tương ứng.

## 19. Public-Safe Representation
* Máy trạm nạn nhân: `IT-ADMIN` (`10.10.35.18`).
* Tệp payload: `SecurityPatch_KB504991.hta`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 93, 108, 115, 116.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 41, 51.
* **Bằng chứng thực nghiệm**: Ảnh chụp bản ghi Sysmon Event ID 1 và màn hình Logger search (Trang 115).
