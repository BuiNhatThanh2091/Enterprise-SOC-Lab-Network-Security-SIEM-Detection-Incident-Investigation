# A02 — Suspicious External Web Download

## 1. Detection ID
A02

## 2. Detection Name
Suspicious External Web Download

## 3. Detection Objective
Phát hiện lưu lượng người dùng từ mạng nội bộ thiết lập kết nối HTTP hướng ngoại tới máy chủ bên ngoài để tải về tệp tin nén chứa mã độc, thông qua chữ ký nhận diện sâu (DPI) của hệ thống Suricata Inline IPS trên tuyến Security Transit.

## 4. Security Context
Nằm ở giai đoạn **Weaponization & Delivery (Mắt xích tải mã độc)** thuộc chuỗi Cyber Kill Chain. Đây là bước mà mồi nhử trong email lừa đảo kích hoạt hành vi tải tệp tin chứa payload độc hại vào trạm làm việc của người dùng.

## 5. Attack Behavior
Người dùng trên máy trạm quản trị kỹ thuật (`IT-ADMIN01`: `10.10.35.18`) nhấp vào liên kết tải bản vá giả mạo trong email (`http://update.kali.test/SecurityPatch_KB504991.zip`), khởi tạo yêu cầu HTTP GET tới máy chủ web của kẻ tấn công (`203.0.113.25:80`).

## 6. Telemetry Source
* **Hệ thống phát sinh**: `SURICATA-IPS01` (Inline IPS trên tuyến Security Transit `10.10.36.11`).
* **Định dạng gốc**: Suricata EVE JSON (`/var/log/suricata/eve.json`).
* **Giao thức truyền**: Syslog TCP qua cổng `5521` (Generator ID 2002) về SmartConnector Linux.

## 7. Observable Evidence
Bản ghi EVE JSON ghi nhận cảnh báo vi phạm chính sách nội tuyến:
* `alert.signature_id = 1101002` (Mã SID tùy biến nhận diện tải tệp nén giả mạo bản vá).
* `alert.signature = "SOC-LAB Suspicious External Archive Download"`
* `sourceAddress = 10.10.35.18` (IP máy trạm trong dải Internal).
* `destinationAddress = 203.0.113.25` (IP máy chủ kẻ tấn công trong dải External).
* `destinationPort = 80`.

## 8. Required Fields
* `deviceProduct`: Phải bằng `"Suricata IDS IPS"`.
* `deviceCustomNumber1` (`cn1Label="SID"`): Bằng `1101002`.
* `sourceAddress`: Thuộc mạng nội bộ (`InSubnet 10.10.35.0/24`).
* `destinationAddress`: Thuộc mạng ngoài biên (`InSubnet 203.0.113.0/24`).

## 9. Detection Logic
Khớp khi Suricata phát hiện một yêu cầu HTTP GET tải tệp nén từ máy trạm nội bộ ra máy chủ ngoài biên, kích hoạt chữ ký nhận diện SID 1101002 trên tuyến Security Transit.

## 10. Logger Validation Query
```text
deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101002 AND sourceAddress=10.10.35.18 AND destinationAddress=203.0.113.25
```

## 11. ESM Logic
```text
(Device Product = Suricata IDS IPS) AND 
(Device Custom Number 1 = 1101002) AND 
(Source Address InSubnet 10.10.35.0/24) AND 
(Target Address InSubnet 203.0.113.0/24)
```

## 12. Threshold / Time Window
Not applicable (Kích hoạt theo từng sự kiện vi phạm chữ ký - Single Event).

## 13. Expected Alert
Cảnh báo mức độ Trung bình (Medium / Severity 6) xuất hiện trên ESM Console:
* Tên hiển thị: `SOC-LAB A02 Suspicious External Web Download`
* Nguồn: `10.10.35.18` | Đích: `203.0.113.25:80` | SID: `1101002`.

## 14. Validation Status
**OBSERVED FIRING** (Đã cấu hình, kiểm chứng qua Logger query và quan sát thấy kích hoạt thực tế trong chuỗi tấn công).

## 15. False Positives / Benign Cases
Người dùng nội bộ tải các tệp tin lưu trữ nén (.zip) hợp lệ từ các máy chủ bên ngoài không thuộc danh sách tin cậy nếu chữ ký Suricata viết quá rộng.

## 16. Investigation Pivot
Khi Rule A02 kích hoạt:
1. Trích xuất địa chỉ IP đích (`destinationAddress` = `203.0.113.25`) và cổng (`80`).
2. Trích xuất địa chỉ IP nguồn nạn nhân (`sourceAddress` = `10.10.35.18`).
3. Truy vấn ngược về máy chủ DNS (`DNS-PUB01`) để tìm bản ghi truy vấn tên miền dẫn đến IP này.
4. Truy vấn xuôi dòng trên máy trạm nạn nhân qua nguồn Sysmon Event ID 1 và ID 11 (FileCreate) để xác định tệp tin nào đã được ghi vào đĩa và tiến trình nào giải nén/thực thi nó.

## 17. Related Detection
* Trước đó: **A01** (Nhận email chứa đường link tải).
* Sau đó: **A03** (Thực thi mã độc HTA), **A04** (Kết nối ngược C2).
* Hợp thành: **C01** (Mắt xích đầu tiên trong bộ ba tương quan Initial Compromise).

## 18. Limitations
Suricata chỉ kiểm tra sâu được nội dung payload khi lưu lượng truyền qua HTTP bản rõ (cổng 80). Nếu tệp tin được tải qua kênh mã hóa HTTPS (`TCP/443`) và Suricata không thực hiện bóc tách chứng chỉ TLS (SSL Decryption), Suricata không thể khớp chữ ký payload mà chỉ quan sát được metadata phiên.

## 19. Public-Safe Representation
* Nguồn nội bộ: `10.10.35.18` (INTERNAL_NET).
* Đích tấn công: `203.0.113.25` (EXTERNAL_NET).
* Tên tệp tải về: `SecurityPatch_KB504991.zip`.

## 20. Source References
* **Tài liệu nguồn**: `Báo cáo đề tài SOC.pdf`, Trang 76, 92, 108, 115.
* **Tài liệu kiến trúc**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Bằng chứng thực nghiệm**: Bản ghi EVE JSON và màn hình Logger search (Trang 115).
