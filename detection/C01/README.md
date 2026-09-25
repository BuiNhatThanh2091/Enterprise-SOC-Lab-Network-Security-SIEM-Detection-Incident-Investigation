# C01 — Initial Compromise Correlation

## 1. Detection ID
C01

## 2. Detection Name
Initial Compromise Correlation (Multi-Source Incident Correlation)

## 3. Detection Objective
Tương quan hóa đa nguồn dữ liệu thời gian thực (Perimeter Network IPS + Endpoint Sysmon + Network Session Metadata) trên công cụ ArcSight ESM Correlation Engine nhằm phát hiện chuỗi hành vi xâm nhập ban đầu hoàn chỉnh gồm: tải tệp nén chứa mã độc (`A02`), kích hoạt thực thi tệp HTA trên máy trạm (`A03`), và phát sinh kết nối điều khiển C2 ngược ra ngoài (`A04`) trên cùng một thực thể máy trạm trong khoảng thời gian trượt $\le 20$ phút.

## 4. Security Context
Nằm ở giai đoạn **Initial Compromise (Tích hợp Initial Access, Execution và Command and Control)** trong Cyber Kill Chain / các kỹ thuật MITRE ATT&CK:
* **Initial Access**: `T1566.001` (Spearphishing Attachment) / `T1189` (Drive-by Compromise / Direct Download)
* **Execution**: `T1218.005` (System Binary Proxy Execution: Mshta)
* **Command and Control**: `T1071.001` (Web Protocols / Reverse Shell TCP/4444)

## 5. Attack Behavior
Kẻ tấn công lừa nạn nhân mở tệp tải về từ email hoặc web thông qua 3 bước liên tiếp:
1. **Bước 1 (Network Ingress)**: Máy trạm nạn nhân `IT-ADMIN01` (`10.10.35.18`) tải tệp nén độc hại `Payroll_Update.zip` từ máy chủ tấn công `203.0.113.25` qua giao thức HTTP (kích hoạt chữ ký Suricata `A02`, SID `1101002`).
2. **Bước 2 (Endpoint Execution)**: Nạn nhân giải nén và mở tệp `Payroll_Update.hta`, kích hoạt tiến trình `mshta.exe` thực thi script độc hại và sinh tiến trình con `powershell.exe` (kích hoạt Sysmon Event ID 1 `A03`).
3. **Bước 3 (Network Egress Callback)**: Đoạn mã độc trên máy trạm ngay lập tức khởi tạo kết nối TCP ngược (Reverse Shell) về cổng `4444` của máy tấn công `203.0.113.25` (kích hoạt phiên kết nối Zeek `conn.log` / Suricata flow `A04`).

## 6. Telemetry Source
Tích hợp đa nguồn từ 3 luồng telemetry độc lập:
1. **Perimeter IPS**: `SURICATA-IPS01` qua EVE JSON Syslog TCP cổng `5521` (Generator ID 2002) — Cảnh báo `A02`.
2. **Endpoint Auditing**: `IT-ADMIN01` Microsoft-Windows-Sysmon Event ID 1 qua Winlogbeat/FlexConnector UDP cổng `5516` (Generator ID 2001) — Cảnh báo `A03`.
3. **Network Session**: `ZEEK-SENSOR01` Zeek `conn.log` qua Syslog TCP cổng `5518` (Generator ID 2003) — Cảnh báo `A04`.

## 7. Observable Evidence
Quy tắc C01 yêu cầu sự hiện diện đồng thời của 3 bằng chứng quan sát được:
* **Sự kiện A02**: `deviceProduct = "Suricata IDS IPS"` AND `deviceCustomNumber1 = 1101002` AND `sourceAddress = 10.10.35.18`.
* **Sự kiện A03**: `externalId = 1` AND `destinationProcessName = "C:\Windows\System32\mshta.exe"` AND `deviceHostName = "IT-ADMIN"`.
* **Sự kiện A04**: `deviceProduct = "Zeek"` AND `transportProtocol = "TCP"` AND `destinationPort = 4444` AND `sourceAddress = 10.10.35.18`.

## 8. Required Fields
* **Khóa tương quan chung (Matching Entity)**: `sourceAddress = 10.10.35.18` (ánh xạ tương ứng với `deviceHostName = "IT-ADMIN"`).
* **Ràng buộc thời gian**: Thời điểm xảy ra sự kiện A04 trừ thời điểm xảy ra sự kiện A02 không vượt quá 20 phút ($\Delta t \le 20\text{ min}$).
* **Trạng thái điều kiện**: Bắt buộc phải có đầy đủ cả 3 cảnh báo con (`A02`, `A03`, `A04`).

## 9. Detection Logic
Sử dụng tính năng Rule Correlation (Event Join / Followed By) của bộ xử lý ArcSight ESM:
* Sự kiện `A02` xuất hiện trên trạm `10.10.35.18`.
* Theo sau bởi sự kiện `A03` xảy ra trên cùng host trong vòng $\le 20$ phút.
* Theo sau bởi sự kiện `A04` xuất phát từ cùng IP nguồn trong vòng $\le 20$ phút.
* ESM khởi tạo một Sự kiện Tương quan (Correlated Event) mới với mức độ nghiêm trọng cấp cao nhất, tự động liên kết ID của 3 sự kiện thành phần.

## 10. Logger Validation Query
```text
name="SOC-LAB C01 Initial Compromise Correlation" OR (deviceProduct="ArcSight" AND message CONTAINS "C01")
```

## 11. ESM Logic
```text
Rule Type: Correlation Rule (Composite Join / Followed By)
Sub-rules:
  - Event 1: Rule A02 (Suspicious External Web Download)
  - Event 2: Rule A03 (Suspicious Script Execution)
  - Event 3: Rule A04 (Suspicious Outbound Callback)
Correlation Condition:
  (Event 1.Target Address == Event 3.Source Address) AND
  (ResolvedHost(Event 1.Target Address) == Event 2.Device Host Name)
Time Window:
  Delta Time (Event 3 - Event 1) <= 20 minutes
Action:
  Create Correlated Event:
    Name: "SOC-LAB C01 Initial Compromise Correlation"
    Severity: 9 (Critical)
    Stage: Initial Compromise
```

## 12. Threshold / Time Window
* **Cửa sổ thời gian trượt**: $\Delta t \le 20\text{ phút}$ (1200 giây).
* **Ràng buộc logic**: Cả 3 điều kiện con phải cùng thỏa mãn trên cùng một thực thể (Entity).

## 13. Expected Alert
Cảnh báo mức độ Tối khẩn cấp (Severity 9-10 / Critical) xuất hiện trên ArcSight ESM Active Channel:
* **Tên hiển thị**: `SOC-LAB C01 Initial Compromise Correlation`
* **Nạn nhân**: `10.10.35.18` (`IT-ADMIN01`)
* **Kẻ tấn công**: `203.0.113.25` (`Kali`)
* **Tóm tắt nội dung**: Chuỗi xâm nhập hoàn chỉnh đã thành công trên máy trạm: Tải tệp nén $\rightarrow$ Kích hoạt `mshta` $\rightarrow$ Kết nối C2 `TCP/4444`.

## 14. Validation Status
**CORRELATION VALIDATED — MULTI-SOURCE INCIDENT** (Đã cấu hình trên ArcSight ESM, kiểm chứng tương quan trong thực nghiệm tấn công trực tiếp và replay, sinh sự kiện tương quan hợp nhất).

## 15. False Positives / Benign Cases
Gần như bằng 0 (Near-Zero False Positive). Trong môi trường doanh nghiệp chuẩn mực, xác suất để một người dùng vô tình tải tệp ZIP, chạy file script `.hta` và phát sinh kết nối `TCP/4444` ra bên ngoài trong vòng 20 phút mà không phải là một cuộc tấn công thực tế là cực kỳ thấp.

## 16. Investigation Pivot
Khi Rule C01 kích hoạt:
1. **Xác định mức độ sự cố**: Lập tức phân loại là Sự cố An ninh Mức 1 (Critical Incident - P1). Máy trạm đã bị kiểm soát hoàn toàn bằng phiên tương tác C2 (Foothold Established).
2. **Kích hoạt phản ứng sự cố**: Thực hiện cô lập máy trạm `10.10.35.18` khỏi mạng nội bộ để ngăn chặn kẻ tấn công chuyển dịch ngang.
3. **Mở luồng điều tra đa chiều**:
   * **Phía trạm (Endpoint)**: Trích xuất lịch sử lệnh PowerShell, kiểm tra bộ nhớ tiến trình `mshta.exe` và `powershell.exe`.
   * **Phía mạng (Network)**: Kiểm tra lưu lượng phiên `TCP/4444` trên Zeek và Suricata để xác định các câu lệnh đầu tiên mà kẻ tấn công đã gửi xuống.
4. **Dự báo hành vi tiếp theo**: Lập tức theo dõi các cảnh báo thăm dò nội bộ (`A05`), thu thập mật khẩu (`A06`) và gom file (`A07`).

## 17. Related Detection
* **Thành phần cấu thành**: **A02** + **A03** + **A04**.
* **Kích hoạt chuỗi theo dõi**: **A05**, **A06**, **A07**, **A08**, **A09**.

## 18. Limitations
* **Khai thác độ trễ thời gian (Temporal Evasion)**: Nếu kẻ tấn công cố tình kéo dài thời gian giữa các bước (ví dụ: gửi mã độc tải về lúc 08:00 nhưng cài đặt chế độ ngủ (sleep) 30 phút sau mới chạy hoặc mở C2 sau hơn 20 phút), cửa sổ tương quan của C01 sẽ bị trôi qua và không kích hoạt cảnh báo hợp nhất. Khi đó chuyên viên SOC phải tự nhận biết qua các cảnh báo nguyên tử đơn lẻ `A02`, `A03`, `A04`.
* **Phụ thuộc tính sẵn sàng đồng thời**: Nếu một trong ba nguồn telemetry (ví dụ Winlogbeat hoặc Sysmon) gặp sự cố dừng thu thập, quy tắc C01 sẽ không thể kích hoạt do thiếu điều kiện cấu thành.

## 19. Public-Safe Representation
* Máy trạm đích: `10.10.35.18` (IT-ADMIN01).
* Máy tấn công: `203.0.113.25` (Kali).
* Cổng C2: `4444`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 78, 107, 108, 110, 125.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 55.
* **Bằng chứng thực nghiệm**: Màn hình cấu hình Rule C01 trong ArcSight ESM Console (Trang 108) và cảnh báo hợp nhất C01 xuất hiện trên Active Channel (Trang 125).
