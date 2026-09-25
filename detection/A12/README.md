# A12 — Suspicious Database Collection

## 1. Detection ID
A12

## 2. Detection Name
Suspicious Database Collection (Schema Enumeration & mysqldump)

## 3. Detection Objective
Phát hiện hành vi thu thập cấu trúc cơ sở dữ liệu và kết xuất dữ liệu hàng loạt (database enumeration & dumping) từ máy chủ DMZ (`WEB01`) sang máy chủ cơ sở dữ liệu nội bộ (`DB01`) bằng cách giám sát các truy vấn metadata đặc trưng của tiện ích `mysqldump` vượt ngưỡng tần suất trong khoảng thời gian ngắn.

## 4. Security Context
Nằm ở giai đoạn **Collection / Discovery (Giai đoạn 8 - Trích xuất cơ sở dữ liệu nội bộ)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1005` (Data from Local System) và `T1087` / `T1082` (System Information Discovery).

## 5. Attack Behavior
Sau khi thu thập được tài khoản cơ sở dữ liệu `_6f9beb897020ebe5` từ tệp cấu hình ở giai đoạn trước, kẻ tấn công thực thi công cụ sao lưu dữ liệu `mysqldump` từ `WEB01` (`10.10.34.13`) hướng sang máy chủ CSDL `DB01` (`10.10.35.19`) để đánh cắp bảng thông tin nhân sự:
```bash
mysqldump -h 10.10.35.19 -u _6f9beb897020ebe5 -p... _6f9beb897020ebe5 tabEmployee | gzip > /tmp/_6f9beb897020ebe5.sql.gz
```
Công cụ `mysqldump` tự động tạo ra một chuỗi truy vấn metadata liên tiếp như `SHOW DATABASES`, `SELECT ... FROM INFORMATION_SCHEMA.FILES WHERE TABLESPACE_NAME ...` để lập chỉ mục các bảng trước khi sao lưu.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `DB01` (`10.10.35.19`) trong phân vùng Internal.
* **Cơ chế thu thập**: MariaDB Audit Plugin (`SERVER_AUDIT`, tham số `server_audit_events = 'CONNECT,QUERY'`). Log ghi tại `/var/log/mysql/server_audit.log`.
* **Định dạng gốc**: MariaDB Audit CSV/Text log.
* **Giao thức truyền**: FlexConnector UDP cổng `5520` (Generator ID 2005) đọc log file và chuyển tiếp dạng CEF tới ArcSight.

## 7. Observable Evidence
* `deviceProduct = "MariaDB Server Audit"`.
* `deviceAction = "query"`.
* `sourceAddress = 10.10.34.13` (WEB01 DMZ).
* `destinationAddress = 10.10.35.19` (DB01 Internal).
* `deviceHostName = "DB01"`.
* `deviceCustomString3` (Trường chứa câu lệnh SQL) chứa:
  * `"SHOW DATABASES"`, HOẶC
  * `"INFORMATION_SCHEMA.FILES"`, HOẶC
  * `"TABLESPACE_NAME"`.

## 8. Required Fields
* `deviceProduct`: Bằng `"MariaDB Server Audit"`.
* `sourceAddress`: Bằng `10.10.34.13`.
* `deviceCustomString3`: Chứa các chuỗi định danh câu lệnh metadata (`SHOW DATABASES`, `INFORMATION_SCHEMA.FILES`, `TABLESPACE_NAME`).

## 9. Detection Logic
Quy tắc tương quan (Correlation Rule) phát hiện khi có ít nhất 2 sự kiện truy vấn metadata schema đặc trưng xuất hiện từ cùng một địa chỉ IP nguồn (`10.10.34.13`) trong cửa sổ thời gian 5 phút.

## 10. Logger Validation Query
```text
deviceProduct="MariaDB Server Audit" AND sourceAddress=10.10.34.13 AND (deviceCustomString3 CONTAINS "SHOW DATABASES" OR deviceCustomString3 CONTAINS "INFORMATION_SCHEMA.FILES" OR deviceCustomString3 CONTAINS "TABLESPACE_NAME")
```

## 11. ESM Logic
```text
Condition:
(Device Product = MariaDB Server Audit) AND 
(Source Address = 10.10.34.13) AND 
((Device Custom String 3 CONTAINS "SHOW DATABASES") OR 
 (Device Custom String 3 CONTAINS "INFORMATION_SCHEMA.FILES") OR 
 (Device Custom String 3 CONTAINS "TABLESPACE_NAME"))

Threshold:
Event Count >= 2
Time Window = 5 minutes
Matching Keys: Source Address, Target Address
```

## 12. Threshold / Time Window
Ngưỡng tối thiểu **2 sự kiện** trong cửa sổ thời gian trượt **5 phút** (`Threshold: 2 in 5m`).

## 13. Expected Alert
Cảnh báo mức độ Cao (Severity 8 / High) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A12 Suspicious Database Collection`
* Tác nhân: `10.10.34.13` $\rightarrow$ Đích: `10.10.35.19`
* Số lượng sự kiện khớp: $\ge 2$ sự kiện schema dump.

## 14. Validation Status
**OBSERVED FIRING — COLLECTION** (Đã cấu hình ngưỡng tương quan trên ESM, kiểm chứng với Logger query ghi nhận 2 sự kiện khớp và cảnh báo ESM kích hoạt thành công).

## 15. False Positives / Benign Cases
Tác vụ sao lưu dữ liệu tự động định kỳ (Scheduled Backup Cron Job) của hệ thống hoặc quản trị viên cơ sở dữ liệu (DBA) thực hiện export bảng phục vụ bảo trì. Cần xác minh thời gian chạy có khớp với lịch vận hành hệ thống đã đăng ký hay không.

## 16. Investigation Pivot
Khi Rule A12 kích hoạt:
1. Xác định database user thực thi trong log (`_6f9beb897020ebe5`) và cơ sở dữ liệu bị nhắm tới.
2. Kiểm tra danh sách các bảng bị truy vấn trong audit log để xác định phạm vi dữ liệu nhạy cảm bị rò rỉ (bảng `tabEmployee`).
3. Truy ngược sang `WEB01` kiểm tra thư mục tạm (`/tmp/`) để tìm kiếm tệp kết xuất nén (ví dụ `_6f9beb897020ebe5.sql.gz`).
4. Thiết lập giám sát cảnh báo tức thời các luồng kết nối dữ liệu ra ngoài Internet từ `WEB01` (`A13`).

## 17. Related Detection
* Trước đó: **A11** (Lấy cắp thông tin đăng nhập database từ container web).
* Tiếp nối bởi: **A13** (Tuồn tệp dữ liệu đã kết xuất ra máy chủ bên ngoài qua mạng).

## 18. Limitations
Quy tắc dựa trên chuỗi lệnh metadata đặc thù của tiện ích `mysqldump` và ngưỡng 2 sự kiện. Nếu kẻ tấn công không dùng `mysqldump` mà tự viết mã (script Python/PHP) thực thi truy vấn trực tiếp `SELECT * FROM tabEmployee;` và lưu kết quả, quy tắc sẽ không phát hiện được do không xuất hiện các chuỗi metadata `SHOW DATABASES` hay `INFORMATION_SCHEMA`.

## 19. Public-Safe Representation
* Máy chủ nguồn: `10.10.34.13` (WEB01 DMZ).
* Máy chủ CSDL đích: `10.10.35.19` (DB01 Internal).
* Người dùng CSDL: `_6f9beb897020ebe5`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 78, 103, 104, 110, 123.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 53.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A12 trong ESM và kết quả Logger query hiển thị 2 events truy vấn MariaDB Server Audit (Trang 104, 123).
