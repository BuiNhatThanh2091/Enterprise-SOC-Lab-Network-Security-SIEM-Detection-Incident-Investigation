# A11 — Sensitive Privileged WEB Activity

## 1. Detection ID
A11

## 2. Detection Name
Sensitive Privileged WEB Activity (Container Config Extraction)

## 3. Detection Objective
Phát hiện hành vi thực thi câu lệnh đặc quyền `sudo docker exec` trên máy chủ DMZ (`WEB01`) nhằm đọc trích xuất các tệp cấu hình chứa thông tin bí mật (database credentials, API keys) từ bên trong ứng dụng web chạy container (`hrms-backend-1`).

## 4. Security Context
Nằm ở giai đoạn **Credential Access / Discovery / Privilege Escalation (Giai đoạn 7 - Chiếm đoạt thông tin xác thực tầng ứng dụng)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1552.001` (Credentials in Files), `T1609` (Container Administration Command) và `T1548.003` (Sudo and Sudo Caching).

## 5. Attack Behavior
Sau khi thiết lập phiên SSH thành công vào `WEB01` (`10.10.34.13`) bằng tài khoản người dùng `thanh`, kẻ tấn công lợi dụng quyền thực thi `sudo` để gọi tiến trình Docker trích xuất tệp cấu hình ứng dụng:
```bash
sudo docker exec -i hrms-backend-1 cat sites/hrms.soclab.internal/site_config.json
```
Lệnh này trả về thông tin xác thực kết nối cơ sở dữ liệu MariaDB, bao gồm tên người dùng `_6f9beb897020ebe5` và mật khẩu truy cập tầng CSDL nội bộ.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `WEB01` (`10.10.34.13`) trong phân vùng DMZ.
* **Cơ chế thu thập**: Linux Auditd (cấu hình audit rule giám sát `/usr/bin/docker` gắn khóa `-k web_exec`) kết hợp `/var/log/auth.log`.
* **Định dạng gốc**: Linux Audit / Syslog.
* **Giao thức truyền**: FlexConnector UDP cổng `5519` (Generator ID 2004).

## 7. Observable Evidence
* `deviceProduct = "WEB01 Web Stack"` (hoặc Linux Auditd/Syslog).
* `deviceAction = "sudo"` (hoặc `execve`).
* `targetUserName = "root"`.
* `deviceProcessName = "/usr/bin/docker"`.
* `message CONTAINS "docker exec"` AND `message CONTAINS "site_config.json"`.
* `deviceHostName = "WEB01"`.

## 8. Required Fields
* `deviceProduct`: Bằng `"WEB01 Web Stack"`.
* `message`: Bắt buộc chứa chuỗi `"docker exec"` VÀ chuỗi `"site_config.json"`.
* `sourceAddress` / `deviceHostName`: Trỏ về máy chủ `WEB01` (`10.10.34.13`).

## 9. Detection Logic
Cảnh báo kích hoạt khi xuất hiện sự kiện thực thi lệnh đặc quyền trên máy chủ web DMZ gọi tới chương trình quản lý container (`docker exec`) nhắm trực tiếp vào tệp cấu hình chứa bí mật (`site_config.json`).

## 10. Logger Validation Query
```text
deviceProduct="WEB01 Web Stack" AND message CONTAINS "docker exec" AND message CONTAINS "site_config.json"
```

## 11. ESM Logic
```text
(Device Product = WEB01 Web Stack) AND 
(Message CONTAINS "docker exec") AND 
(Message CONTAINS "site_config.json")
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Cao (Severity 7 / High) trên ArcSight ESM Console:
* Tên hiển thị: `SOC-LAB A11 Sensitive Privileged WEB Activity`
* Host: `WEB01` (`10.10.34.13`)
* Thông điệp: `sudo: thanh : TTY=pts/1 ; PWD=/home/thanh ; USER=root ; COMMAND=/usr/bin/docker exec -i hrms-backend-1 cat ... site_config.json`

## 14. Validation Status
**OBSERVED FIRING — EXPLOITATION / CREDENTIAL ACCESS** (Đã cấu hình trên ESM, truy vấn thành công trên Logger và kích hoạt thực tế khi kẻ tấn công trích xuất config).

## 15. False Positives / Benign Cases
Hoạt động triển khai cấu hình, nâng cấp hoặc gỡ lỗi chính thức của kỹ sư DevOps/System Admin. Tuy nhiên, trong môi trường sản xuất nghiêm ngặt, việc đọc trực tiếp tệp cấu hình production bằng lệnh ad-hoc qua SSH là hành vi bất thường cần kiểm tra Change Request (CR).

## 16. Investigation Pivot
Khi Rule A11 kích hoạt:
1. Xác định tài khoản Linux và TTY thực thi lệnh (trong log là `thanh` trên `pts/1`).
2. Truy ngược lại Rule `A10` và `/var/log/auth.log` để xác định địa chỉ IP nguồn khởi tạo phiên SSH vào `WEB01`.
3. Trích xuất tên database user bị lộ (`_6f9beb897020ebe5`).
4. Pivot ngay lập tức sang phân vùng Internal Database `DB01` (`10.10.35.19`) theo dõi các truy vấn bất thường hoặc hành vi trích xuất cơ sở dữ liệu (`A12`).

## 17. Related Detection
* Trước đó: **A10** (Phiên SSH từ mạng nội bộ vào Web DMZ).
* Tiếp nối bởi: **A12** (Truy vấn thu thập dữ liệu và dump database từ Web sang DB).

## 18. Limitations
Auditd giám sát câu lệnh thực thi tại host OS (`WEB01`). Nếu kẻ tấn công mở một phiên tương tác interactive shell bên trong container (`docker exec -it hrms-backend-1 /bin/bash`) rồi mới đọc file từ bên trong container shell, Auditd của host sẽ chỉ ghi nhận lệnh khởi tạo `/bin/bash` mà không bắt được nội dung các lệnh con bên trong PID namespace của container (trừ khi có container security agent chuyên biệt).

## 19. Public-Safe Representation
* Máy chủ Web: `WEB01` (`10.10.34.13`).
* Tên tệp cấu hình chuẩn hóa: `sites/hrms.soclab.internal/site_config.json`.
* Database User: `_6f9beb897020ebe5`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 78, 101, 102, 110, 122.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 52.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule A11 trong ESM và kết quả Logger query sự kiện sudo docker exec (Trang 102, 122).
