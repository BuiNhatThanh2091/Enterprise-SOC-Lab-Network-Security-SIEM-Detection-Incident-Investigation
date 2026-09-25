# A04 — Suspicious Outbound Callback

## 1. Detection ID
A04

## 2. Detection Name
Suspicious Outbound Callback (Zeek Network Flow)

## 3. Detection Objective
Phát hiện phiên kết nối mạng hướng ngoại bất thường (Reverse Shell / Command and Control Callback) khởi tạo từ máy trạm nội bộ ra máy chủ ngoài biên trên cổng phi tiêu chuẩn `TCP/4444`, thông qua dữ liệu phân tích luồng mạng thụ động từ cảm biến Zeek NDR.

## 4. Security Context
Nằm ở giai đoạn **Command and Control (Giai đoạn 3 - Điều khiển từ xa)** trong Cyber Kill Chain / kỹ thuật MITRE ATT&CK `T1095` (Non-Application Layer Protocol) và `T1571` (Non-Standard Port).

## 5. Attack Behavior
Sau khi tiến trình ngầm `powershell.exe` được kích hoạt trên `IT-ADMIN01` (`10.10.35.18`), mã độc chủ động tạo socket TCP kết nối ngược ra cổng lắng nghe của máy tấn công Kali (`203.0.113.25:4444`), bàn giao phiên tương tác dòng lệnh (Interactive Shell) cho kẻ tấn công.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `ZEEK-NDR01` (Cảm biến giám sát mạng thụ động qua SPAN/gretap).
* **Định dạng gốc**: Zeek TSV `conn.log`.
* **Giao thức truyền**: Rsyslog UDP qua cổng `5518` (Generator ID 2003) về SmartConnector Linux.

## 7. Observable Evidence
Bản ghi siêu dữ liệu phiên kết nối mạng:
* `transportProtocol = "TCP"`
* `sourceAddress = 10.10.35.18` (Subnet Internal).
* `destinationAddress = 203.0.113.25` (Subnet External).
* `destinationPort = 4444`.
* `deviceCustomString2 = "C9xKa811"` (`cs2Label="ZeekUID"`).
* Thời lượng phiên kết nối kéo dài (`duration > 0`), có trao đổi byte hai chiều (`orig_bytes > 0`, `resp_bytes > 0`).

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Zeek"`.
* `transportProtocol`: Bằng `"TCP"`.
* `sourceAddress`: Thuộc mạng nội bộ (`InSubnet 10.10.35.0/24`).
* `destinationAddress`: Thuộc mạng ngoài biên (`InSubnet 203.0.113.0/24`).
* `destinationPort`: Bằng `4444`.

## 9. Detection Logic
Khớp khi Zeek ghi nhận một phiên kết nối TCP hướng ngoại từ dải mạng nội bộ ra dải mạng ngoài biên trên cổng đích 4444.

## 10. Logger Validation Query
```text
deviceProduct="Zeek" AND sourceAddress=10.10.35.18 AND destinationAddress=203.0.113.25 AND destinationPort=4444
```

## 11. ESM Logic
```text
(Name Contains Zeek Connection) AND 
(Transport Protocol = TCP) AND 
(Attacker Address InSubnet 10.10.35.0/24) AND 
(Destination Address InSubnet 203.0.113.0/24) AND 
(Target Port = 4444)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng bản ghi phiên mạng).

## 13. Expected Alert
Cảnh báo mức độ Cao (High / Severity 8) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A04 Suspicious Outbound Callback`
* Cổng đích: `4444` | IP nguồn: `10.10.35.18` | IP đích: `203.0.113.25`.

## 14. Validation Status
**OBSERVED FIRING — SCENARIO-DEPENDENT (VOLUME LIMITED)** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế).

## 15. False Positives / Benign Cases
Các dịch vụ nội bộ chạy kiểm thử phần mềm trên cổng 4444 (rất hiếm khi kết nối ra ngoài Internet).

## 16. Investigation Pivot
Khi Rule A04 kích hoạt:
1. Trích xuất mã phiên `ZeekUID` (`deviceCustomString2`) để xem tổng thời lượng và dung lượng truyền tải.
2. Trích xuất thời điểm bắt đầu phiên kết nối ($T_{\text{C2}}$) và cổng nguồn phía máy trạm (`sourcePort` = `49715`).
3. Chuyển hướng sang nguồn Sysmon Event ID 3 trên máy trạm với điều kiện `destinationPort = 4444` để tìm `ProcessGuid` của tiến trình đã mở kết nối này.
4. Lần ngược về `ParentProcessGuid` để tìm nguồn gốc phần mềm độc hại.

## 17. Related Detection
* Trước đó: **A03** (Thực thi script HTA tạo Reverse Shell).
* Tiếp nối bởi: **A05** (Trinh sát nội bộ qua phiên tương tác vừa mở).
* Hợp thành: **C01** (Mắt xích thứ ba khép lại bộ ba tương quan Initial Compromise).

## 18. Limitations
1. **Scenario Dependency**: Rule được xây dựng dựa trên cổng kết nối biết trước của bài lab kiểm thử (`TCP/4444`). Nếu kẻ tấn công đổi cổng sang các cổng phổ biến (`443`, `80`, `8080`), rule này sẽ không phát hiện được.
2. **Alert Volume Flooding**: Do phiên kết nối tương tác dòng lệnh duy trì liên tục, Zeek đẩy liên tục các bản ghi cập nhật trạng thái phiên. Điều này tạo ra hiện tượng **trùng lặp cảnh báo dày đặc (Alert Flooding)** trên ESM Console, buộc SOC Analyst phải áp dụng bộ lọc loại trừ tạm thời (`Name != "A04*"`) trên Active Channel chính để quan sát các cảnh báo khác.

## 19. Public-Safe Representation
* Nguồn nội bộ: `10.10.35.18` (IT-ADMIN01).
* Đích ngoại vi: `203.0.113.25` (KALI-ATTACKER).
* Cổng điều khiển: `4444`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 77, 94, 106, 107, 108, 116.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 19, 51.
* **Bằng chứng thực nghiệm**: Màn hình Active Channel phân tích alert volume (Trang 106) và Logger query `conn.log` (Trang 116).
