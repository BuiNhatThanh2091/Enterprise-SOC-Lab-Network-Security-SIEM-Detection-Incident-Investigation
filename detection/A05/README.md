# A05 — Post-Compromise Discovery Burst

## 1. Detection ID
A05

## 2. Detection Name
Post-Compromise Discovery Burst

## 3. Detection Objective
Nhận diện chuỗi hành vi trinh sát nội bộ dồn dập (Discovery Burst) diễn ra trên máy trạm ngay sau khi kẻ tấn công chiếm được quyền tương tác dòng lệnh, thông qua việc phát hiện mật độ xuất hiện dày đặc của các câu lệnh kiểm tra dịch vụ mạng, phiên đăng nhập và khóa xác thực.

## 4. Security Context
Nằm ở giai đoạn **Discovery (Giai đoạn 4 - Trinh sát nội bộ)** trong mô hình Cyber Kill Chain / các kỹ thuật MITRE ATT&CK: `T1082` (System Information Discovery), `T1007` (System Service Discovery), `T1033` (System Owner/User Discovery), `T1049` (System Network Connections Discovery).

## 5. Attack Behavior
Sau khi có phiên Reverse Shell trên `IT-ADMIN01` (`10.10.35.18`), kẻ tấn công thực thi liên tiếp các câu lệnh trong cửa sổ ngắn: `where ssh`, `sc query termservice`, `sc query sshd`, `qwinsta`, `netstat -an`, `type .ssh\config` để xác định các mục tiêu quản trị tiềm năng.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Máy trạm Windows 10 Pro `10.10.35.18`).
* **Định dạng gốc**: Microsoft Sysmon Event ID 1 (Process Create) định dạng XML.
* **Giao thức truyền**: Windows Event Forwarding (WEC) / ArcSight Native Connector (Generator ID 2009).

## 7. Observable Evidence
Chuỗi các sự kiện tạo tiến trình liên tiếp chứa các tham số dòng lệnh khảo sát đặc quyền:
* `externalId = 1`
* `deviceCustomString4` chứa các mẫu: `"where ssh"`, `"sc query"`, `"netstat"`, `".ssh"`, `"qwinsta.exe"`, `"ssh-keygen.exe"`.
* Mật độ thực thi: Đạt ngưỡng $\ge 3\text{ lệnh}$ trong vòng 5 phút.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Sysmon"`.
* `externalId`: Bằng `1`.
* `deviceHostName`: `"IT-ADMIN"`.
* `deviceCustomString4`: Chứa các từ khóa trinh sát (kết hợp logic `OR`).

## 9. Detection Logic
Quy tắc ngưỡng (Threshold Rule): Kích hoạt khi ghi nhận ít nhất 3 sự kiện Sysmon Event ID 1 trên cùng một máy trạm chứa các câu lệnh trinh sát hệ thống trong cửa sổ thời gian 5 phút.

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND deviceProduct="Sysmon" AND externalId=1 AND (deviceCustomString4 CONTAINS "where ssh" OR deviceCustomString4 CONTAINS ".ssh" OR destinationProcessName CONTAINS "qwinsta.exe")
```

## 11. ESM Logic
```text
(External ID = 1) AND 
(Device Product = Sysmon) AND 
(
    (Device Custom String 4 Contains where) OR 
    (Device Custom String 4 Contains sc query) OR 
    (Device Custom String 4 Contains query session) OR 
    (Device Custom String 4 Contains netstat) OR 
    (Device Custom String 4 Contains .ssh) OR 
    (Target Process Name Contains qwinsta.exe) OR 
    (Target Process Name Contains ssh-keygen.exe)
)
```
* **Aggregation**: Group by `deviceHostName`.
* **Threshold**: $\text{Matches} \ge 3$ sự kiện trong $5\text{ phút}$.

## 12. Threshold / Time Window
* **Ngưỡng kích hoạt**: $\ge 3\text{ sự kiện}$.
* **Cửa sổ thời gian**: $5\text{ phút}$ ($300\text{ giây}$).

## 13. Expected Alert
Cảnh báo mức độ Trung bình - Cao (Medium-High / Severity 7) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A05 Post-Compromise Discovery Burst`
* Host: `IT-ADMIN` | Số lượng lệnh kích hoạt: $\ge 3$.

## 14. Validation Status
**OBSERVED FIRING — THRESHOLD-BASED** (Đã cấu hình ngưỡng 3 sự kiện/5 phút và quan sát thấy kích hoạt thực tế khi kịch bản chạy burst lệnh).

## 15. False Positives / Benign Cases
Quản trị viên hệ thống hoặc kỹ sư IT thực hiện xử lý sự cố (troubleshooting) thủ công trên máy trạm cũng có thể gõ các câu lệnh như `netstat` hoặc `sc query`.

## 16. Investigation Pivot
Khi Rule A05 kích hoạt:
1. Xác định tài khoản đang thực thi (`destinationUserName`).
2. Trích xuất mã `ProcessGuid` của tiến trình cha để xác định môi trường gọi lệnh (cmd/powershell từ reverse shell hay người dùng đăng nhập console).
3. Lần theo các sự kiện tiếp theo để tìm dấu hiệu đánh cắp thông tin xác thực (`A06`).

## 17. Related Detection
* Trước đó: **A04** (Mở Reverse Shell).
* Tiếp nối bởi: **A06** (Thu thập hồ sơ trình duyệt Firefox), **A07** (Nén và chuyển tệp).

## 18. Limitations
Do phụ thuộc vào ngưỡng **3 sự kiện trong 5 phút**, nếu kẻ tấn công thực thi trinh sát giãn cách thời gian (chẳng hạn mỗi lệnh cách nhau 10 phút), quy tắc này sẽ không kích hoạt cảnh báo.

## 19. Public-Safe Representation
* Máy trạm nạn nhân: `IT-ADMIN` (`10.10.35.18`).
* Không chứa thông tin định danh cá nhân nhạy cảm.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 94, 95, 109, 116, 117.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A05 trong ESM và Logger query kết quả 9 events (Trang 95, 117).
