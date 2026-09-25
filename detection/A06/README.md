# A06 — Credential Material Collection

## 1. Detection ID
A06

## 2. Detection Name
Credential Material Collection (Browser Profile Staging)

## 3. Detection Objective
Phát hiện hành vi thu thập và sao chép trái phép thư mục hồ sơ (profile) của trình duyệt web Mozilla Firefox từ thư mục dữ liệu cá nhân của người dùng sang thư mục chia sẻ công cộng, nhằm mục đích đánh cắp thông tin đăng nhập và mật khẩu đã lưu.

## 4. Security Context
Nằm ở giai đoạn **Credential Access & Staging (Giai đoạn 5 - Thu thập thông tin xác thực)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1555.003` (Credentials from Web Browsers) và `T1552.001` (Credentials in Files).

## 5. Attack Behavior
Sau khi phát hiện khóa SSH có cài đặt passphrase và không thể dump bộ nhớ LSASS do giới hạn quyền, kẻ tấn công chuyển hướng khai thác mật khẩu lưu trên trình duyệt web. Kẻ tấn công sử dụng tiện ích `xcopy.exe` sao chép toàn bộ thư mục hồ sơ Firefox (`waut035y.default-release`) sang thư mục trung chuyển công cộng `C:\Users\Public\firefox_profile\`.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `IT-ADMIN01` (Máy trạm Windows 10 Pro `10.10.35.18`).
* **Định dạng gốc**: Microsoft Sysmon Event ID 1 (Process Create) định dạng XML.
* **Giao thức truyền**: Windows Event Forwarding (WEC) / ArcSight Native Connector (Generator ID 2009).

## 7. Observable Evidence
Bản ghi tạo tiến trình trên máy trạm:
* `externalId = 1`
* `destinationProcessName = "C:\Windows\System32\xcopy.exe"`
* `deviceCustomString4` chứa tham số: `"Mozilla\Firefox\Profiles"` và `"\Users\Public\"`.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Sysmon"`.
* `externalId`: Bằng `1`.
* `destinationProcessName`: Chứa `"xcopy.exe"`.
* `deviceCustomString4`: Chứa `"Mozilla\Firefox\Profiles"` và `"\Users\Public\"`.

## 9. Detection Logic
Khớp khi tiến trình `xcopy.exe` được kích hoạt và dòng lệnh chứa chuỗi đường dẫn nguồn là thư mục Profile của Firefox cùng đường dẫn đích là thư mục `\Users\Public\`.

## 10. Logger Validation Query
```text
deviceHostName="IT-ADMIN" AND deviceProduct="Sysmon" AND externalId=1 AND destinationProcessName CONTAINS "xcopy.exe" AND deviceCustomString4 CONTAINS "Firefox\Profiles"
```

## 11. ESM Logic
```text
(External ID = 1) AND 
(Device Product = Sysmon) AND 
(Target Process Name Contains xcopy.exe) AND 
(Device Custom String 4 Contains Mozilla\Firefox) AND 
(Device Custom String 4 Contains \Users\Public\)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Rất Cao (Critical / Severity 8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A06 Credential Material Collection`
* Tiến trình: `xcopy.exe` | Thư mục tác động: `Firefox\Profiles`.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Người dùng hoặc tập lệnh sao lưu cục bộ (backup script) thực hiện sao lưu thủ công hồ sơ trình duyệt vào thư mục chia sẻ công cộng (rất bất thường và vi phạm chính sách an ninh doanh nghiệp).

## 16. Investigation Pivot
Khi Rule A06 kích hoạt:
1. Xác định ngay tài khoản người dùng có hồ sơ bị sao chép.
2. Kiểm tra các câu lệnh PowerShell tiếp theo qua Event ID 4104 để xem tệp profile có bị nén (.zip) hoặc chuyển ra ngoài không (`A07`).
3. Khởi tạo quy trình thu hồi và đổi mật khẩu toàn diện cho các tài khoản mà người dùng này từng đăng nhập qua trình duyệt (đặc biệt là tài khoản quản trị `thanh` trên máy chủ Web).

## 17. Related Detection
* Trước đó: **A05** (Trinh sát phát hiện Firefox).
* Tiếp nối bởi: **A07** (Nén zip và mở raw socket đẩy tệp profile ra ngoài).

## 18. Limitations
Rule chỉ bắt hành vi sao chép profile bằng `xcopy.exe` vào thư mục `\Users\Public\`. Nếu kẻ tấn công sử dụng công cụ chuyên dụng (như Mimikatz, Lazagne) hoặc đọc trực tiếp tệp SQLite của trình duyệt bằng script nhúng bộ nhớ, Rule A06 sẽ không phát hiện được. Đồng thời, hành vi này chỉ là *sao chép hồ sơ*, việc giải mã mật khẩu thực tế diễn ra ngoại tuyến (offline) trên máy Kali nên SIEM không thể ghi nhận bước giải mã.

## 19. Public-Safe Representation
* Đường dẫn nguồn: `C:\Users\<User>\AppData\Roaming\Mozilla\Firefox\Profiles\`.
* Đường dẫn đích: `C:\Users\Public\firefox_profile\`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 95, 96, 109, 117.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Ảnh chụp bản ghi Sysmon Event ID 1 và màn hình Logger search (Trang 96, 117).
