# A01 — Mail Delivered to Internal User

## 1. Detection ID
A01

## 2. Detection Name
Mail Delivered to Internal User

## 3. Detection Objective
Ghi nhận sự kiện máy chủ thư điện tử nội bộ chuyển phát thành công một bức thư vào hộp thư người dùng thuộc miền `soclab.test`. Rule này không đánh giá bản thân bức thư là độc hại mà đóng vai trò là một sự kiện ngữ cảnh nền tảng (Contextual / Baseline Event) xác lập mốc thời gian tiếp nhận thư để làm điểm neo (Anchor) cho quá trình đối soát chuỗi tấn công sau này.

## 4. Security Context
Nằm ở bước khởi đầu của giai đoạn **Initial Access (Giai đoạn 1 - Delivery)** trong mô hình Cyber Kill Chain. Đây là mắt xích ghi nhận bức thư mang mồi nhử lừa đảo (Spear-phishing) đã vượt qua hàng rào tiếp nhận và nằm trong tầm tiếp cận của người dùng nội bộ.

## 5. Attack Behavior
Kẻ tấn công từ máy chủ ngoại vi (`KALI-ATTACKER`: `203.0.113.25`) thực thi kịch bản Python gửi email lừa đảo mạo danh `security@microsoft.com` với tiêu đề "URGENT: Critical Security Update KB504991" tới hộp thư người dùng `user01@soclab.test`.

## 6. Telemetry Source
* **Hệ thống phát sinh**: `MAIL01` (Máy chủ Postfix Mail Server tại phân vùng DMZ `10.10.34.14`).
* **Định dạng gốc**: Postfix Syslog text (`/var/log/mail.log`).
* **Giao thức truyền**: Syslog UDP qua cổng `5516` (Generator ID 2007) về SmartConnector Linux.

## 7. Observable Evidence
Bản ghi nhật ký dịch vụ Postfix xác nhận hoàn tất tiến trình phân phối cục bộ (local delivery):
* `name = "Postfix Local Delivery"`
* `deviceAction = "sent"`
* `destinationUserName = "user01@soclab.test"`
* `deviceCustomString3 = "718FC8006A"` (Postfix Queue ID)

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Postfix Mail Server"`.
* `name`: Phải bằng `"Postfix Local Delivery"`.
* `deviceAction`: Phải bằng `"sent"`.
* `destinationUserName`: Phải có đuôi kết thúc `ENDSWITH "@soclab.test"`.
* `deviceCustomString3` (`cs3Label="QueueID"`): Chứa mã định danh hàng đợi duy nhất.

## 9. Detection Logic
Kích hoạt khi một bản ghi Postfix ghi nhận hành động phân phối thư thành công (`sent`) tới bất kỳ tài khoản nào thuộc không gian tên miền nội bộ `@soclab.test`.

## 10. Logger Validation Query
```text
deviceProduct="Postfix Mail Server" AND name="Postfix Local Delivery" AND deviceAction="sent" AND destinationUserName="user01@soclab.test"
```

## 11. ESM Logic
```text
(Device Product = Postfix Mail Server) AND 
(Name = Postfix Local Delivery) AND 
(Device Action = sent) AND 
(Target User Name EndsWith @soclab.test)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt tức thời theo từng sự kiện đơn lẻ - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Thông tin / Ngữ cảnh (Informational / Severity 1–2) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A01 External Mail Delivered to Internal User`
* Thông tin kèm theo: Tài khoản nhận `user01@soclab.test`, trạng thái `sent`.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế trên giao diện Active Channel của ESM).

## 15. False Positives / Benign Cases
Toàn bộ các luồng trao đổi thư tín công việc hợp lệ gửi đến nhân viên công ty đều kích hoạt quy tắc này. Do đó, A01 tuyệt đối không được gán mức độ nghiêm trọng cao hoặc dùng làm căn cứ cô lập hệ thống đơn độc.

## 16. Investigation Pivot
Khi có cảnh báo tấn công điểm cuối xảy ra sau đó:
1. Trích xuất mốc thời gian nhận thư ($T_{\text{mail}}$) và tài khoản nhận (`destinationUserName`).
2. Trích xuất mã hàng đợi `Queue ID` (`deviceCustomString3` = `718FC8006A`).
3. Truy vấn ngược về sự kiện kết nối SMTP trước đó trên Logger bằng `Queue ID` để xác định địa chỉ IP nguồn thực tế của máy gửi (`203.0.113.25`) và địa chỉ email gửi (`security@microsoft.com`).

## 17. Related Detection
* Tiếp nối bởi: **A02** (Tải tệp tin nén ngoại vi qua Suricata IPS khi nạn nhân bấm vào đường link trong thư).
* Nằm trong chuỗi điều tra: **C01** (Initial Compromise Correlation).

## 18. Limitations
Sự kiện `Postfix Local Delivery` chỉ chứng minh thư đã được đưa vào hộp thư cục bộ. Bản ghi này **không chứa địa chỉ IP nguồn ban đầu của máy gửi bên ngoài Internet**. Thông tin IP ngoài nằm ở sự kiện kết nối SMTP trước đó trong chuỗi xử lý của Postfix.

## 19. Public-Safe Representation
* Tên miền đích: `@soclab.test` (RFC 2606 / RFC 6761).
* Hộp thư nạn nhân: `user01@soclab.test`.
* IP máy chủ Mail: `10.10.34.14` (DMZ_NET).

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 76, 91, 107, 114.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 43, 51.
* **Bằng chứng thực nghiệm**: Ảnh chụp màn hình Active Channel và Logger search kết quả Queue ID `718FC8006A` (Trang 107, 114).
