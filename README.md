# 🚀 NetScanner - Advanced Network Security Tool

<div align="center">

![NetScanner](https://img.shields.io/badge/NetScanner-Advanced%20Network%20Security-blue)
![Python](https://img.shields.io/badge/Python-3.6+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Unix-orange)

**Công cụ quét mạng và kiểm tra bảo mật nâng cao**

*Phát hiện thiết bị, phân tích mạng và thực hiện các bài kiểm tra bảo mật*

</div>

---

## ⚠️ **CẢNH BÁO QUAN TRỌNG**

**🔴 CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU!**

- ✅ **Được phép**: Mạng riêng của bạn, mạng được cấp phép
- ❌ **KHÔNG được phép**: Mạng công cộng, mạng của người khác
- ⚖️ **Trách nhiệm**: Người dùng chịu hoàn toàn trách nhiệm về việc sử dụng

---

## 🎯 **Tính Năng Chính**

### 🔍 **Network Discovery**
- **Quét mạng LAN** - Phát hiện tất cả thiết bị trong mạng
- **Nhận diện thiết bị** - Phân tích vendor, OS, hostname
- **Lưu trữ thông minh** - Database JSON với thông tin chi tiết
- **Giao diện đẹp** - CLI với màu sắc và bảng thông tin

### ⚡ **DDoS Attack Module** (Giáo dục)
- **7 loại tấn công**: SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Slowloris, DNS Amplification, Mixed
- **Tấn công đa mục tiêu**: Đồng loạt nhiều thiết bị hoặc 1 thiết bị cụ thể
- **Chế độ cực mạnh**: 50 threads/target, 20,000 pps
- **Menu tương tác**: Chọn target, loại tấn công, cường độ
- **Giám sát real-time**: Thống kê packets, pps, errors

### 🕵️ **MITM Attack Module** (Giáo dục)
- **ARP Poisoning**: Chặn và phân tích lưu lượng mạng
- **Packet Sniffing**: Bắt và phân tích gói tin TCP/UDP
- **Tấn công đơn/multiple**: 1 target hoặc luân phiên nhiều target
- **Real-time Analysis**: Phân tích lưu lượng theo thời gian thực

### 🛠️ **Utilities**
- **Dọn dẹp tự động**: Xóa logs, cache files
- **Interface Detection**: Tự động phát hiện card mạng
- **Root Check**: Kiểm tra quyền admin
- **Error Handling**: Xử lý lỗi thông minh

---

## 📦 **Cài Đặt**

### **Yêu Cầu Hệ Thống**
```bash
# Hệ điều hành
- Linux (Ubuntu, Kali, Debian)
- macOS (có thể cần điều chỉnh)

# Python
- Python 3.6+

# Quyền
- Root privileges (sudo)
```

### **Cài Đặt Dependencies**
```bash
# Clone repository
git clone <your-repo-url>
cd netscanner

# Tạo virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# hoặc
venv\Scripts\activate     # Windows

# Cài đặt dependencies
pip install -r requirements.txt

# Cài đặt nmap (Ubuntu/Debian)
sudo apt update
sudo apt install nmap
```

---

## 🚀 **Sử Dụng**

### **Khởi Động**
```bash
# Chạy với quyền root (bắt buộc)
sudo python3 cli.py

# Hoặc kích hoạt venv trước
source venv/bin/activate
sudo python3 cli.py
```

### **Các Lệnh Có Sẵn**

```bash
netscanner> help

# Quét mạng
netscanner> scan          # Quét nhanh
netscanner> scan -v       # Quét chi tiết (vendor + OS)

# Tấn công (Giáo dục)
netscanner> ddos          # Tấn công DDoS với menu
netscanner> ddos --port 80 --debug  # Tùy chọn nâng cao
netscanner> mitm          # Tấn công Man-in-the-Middle

# Utilities
netscanner> clean         # Dọn dẹp logs và cache
netscanner> exit          # Thoát
```

---

## 🎮 **Hướng Dẫn Chi Tiết**

### **1. Quét Mạng**
```bash
netscanner> scan -v

[*] Đang quét chi tiết (loại thiết bị + hệ điều hành)...
[+] Tìm thấy Interface: wlan0, IP: 192.168.1.100

📱 Thiết bị đã tìm thấy:
┌─────────────────┬──────────────────────┬─────────────────────────────────┬──────────────────┐
│ IP Address      │ MAC Address          │ Vendor                          │ OS               │
├─────────────────┼──────────────────────┼─────────────────────────────────┼──────────────────┤
│ 192.168.1.1     │ aa:bb:cc:dd:ee:ff    │ TP-Link Technologies            │ Linux 3.2-4.9   │
│ 192.168.1.10    │ 11:22:33:44:55:66    │ Samsung Electronics             │ Android          │
│ 192.168.1.15    │ 77:88:99:aa:bb:cc    │ Apple Inc.                      │ iOS/macOS        │
└─────────────────┴──────────────────────┴─────────────────────────────────┴──────────────────┘

[+] Tìm thấy 15 thiết bị trong mạng
[+] Kết quả đã được lưu vào devices.txt
```

### **2. Tấn Công DDoS (Giáo dục)**
```bash
netscanner> ddos

=== DDoS ATTACK MODULE ===
1. Tấn công đồng loạt nhiều thiết bị
2. Tấn công 1 thiết bị cụ thể

=== CHỌN LOẠI TẤN CÔNG ===
1. TCP SYN Flood
2. UDP Flood
3. ICMP Flood
4. Mixed Attack
5. HTTP Flood
6. Slowloris Attack
7. DNS/NTP Amplification

=== CHẾ ĐỘ TẤN CÔNG ===
1. Tấn công bình thường
2. Tấn công cực mạnh (⚠️ CẢNH BÁO: Có thể gây sập mạng!)

[*] Tấn công đã bắt đầu với 50 luồng. Nhấn Ctrl+C để dừng.
Thống kê: 15000 gói tin, 8000.0 pps, 0 lỗi, 5 mục tiêu online
```

### **3. Tấn Công MITM (Giáo dục)**
```bash
netscanner> mitm

=== MITM ATTACK MODULE ===
1. Tấn công 1 thiết bị cụ thể
2. Tấn công nhiều thiết bị (luân phiên)

[*] Bắt đầu ARP Poisoning...
[*] Đang giám sát lưu lượng mạng...
[+] Bắt được gói tin TCP: 192.168.1.10:443 -> 192.168.1.1:80
[+] Phân tích HTTP request...
```

---

## 📁 **Cấu Trúc Project**

```
netscanner/
├── 📄 cli.py                 # Giao diện CLI chính
├── 📄 core.py                # Engine chính
├── 📄 requirements.txt       # Dependencies
├── 📄 README.md             # Tài liệu này
├── 📁 modules/
│   ├── 📄 scanner.py         # Module quét mạng
│   ├── 📄 ddos.py           # Module DDoS attack
│   └── 📄 mitm.py           # Module MITM attack
├── 📁 venv/                 # Virtual environment
├── 📄 devices.txt           # Database thiết bị (JSON)
└── 📄 *.log                 # Log files
```

---

## 🔧 **Cấu Hình Nâng Cao**

### **DDoS Attack Parameters**
```python
# Trong modules/ddos.py
threads_per_target = 10      # Số luồng mỗi target
packet_rate = 5000          # Packets per second
aggressive_mode = False     # Chế độ cực mạnh
```

### **MITM Attack Parameters**
```python
# Trong modules/mitm.py
poison_interval = 2         # Thời gian ARP poisoning
enable_sniffing = True      # Bật packet sniffing
```

---

## 📊 **Output Examples**

### **Network Scan Results**
```json
{
  "192.168.1.10": {
    "mac": "11:22:33:44:55:66",
    "hostname": "Samsung-Galaxy",
    "vendor": "Samsung Electronics",
    "os": "Android",
    "status": "up",
    "last_seen": "2024-01-15 10:30:00"
  }
}
```

### **Attack Statistics**
```
Thống kê: 25000 gói tin, 12000.0 pps, 5 lỗi, 8 mục tiêu online
Tấn công đã dừng. Tổng kết: 25000 gói tin, 12000.0 pps trung bình, 5 lỗi
```

---

## 🛡️ **Bảo Mật & Ethics**

### **Nguyên Tắc Sử Dụng**
- ✅ **Chỉ sử dụng trên mạng của bạn**
- ✅ **Mục đích giáo dục và nghiên cứu**
- ✅ **Tuân thủ luật pháp địa phương**
- ❌ **Không tấn công mạng công cộng**
- ❌ **Không sử dụng cho mục đích xấu**

### **Bảo Vệ Mạng**
```bash
# Cách phát hiện tấn công
- Giám sát lưu lượng mạng bất thường
- Cài đặt firewall và IDS
- Cập nhật firmware router
- Sử dụng VPN cho kết nối quan trọng
```

---

## 🐛 **Troubleshooting**

### **Lỗi Thường Gặp**

**1. Permission Denied**
```bash
# Giải pháp: Chạy với sudo
sudo python3 cli.py
```

**2. Interface Not Found**
```bash
# Kiểm tra interface
ip addr show
# Hoặc chọn interface thủ công trong menu
```

**3. No Targets Found**
```bash
# Chạy scan trước
netscanner> scan
# Sau đó chạy attack
netscanner> ddos
```

**4. Import Error**
```bash
# Kích hoạt virtual environment
source venv/bin/activate
# Cài đặt lại dependencies
pip install -r requirements.txt
```

---

## 📝 **Changelog**

### **v2.0.0** (Current)
- ✨ **DDoS Module**: 7 loại tấn công, chế độ cực mạnh
- ✨ **MITM Module**: ARP poisoning, packet sniffing
- ✨ **Interactive Menus**: Chọn target, loại tấn công
- ✨ **Clean Command**: Dọn dẹp logs và cache
- ✨ **Enhanced Logging**: Real-time statistics
- ✨ **Better Error Handling**: User-friendly messages

### **v1.0.0**
- 🔍 **Network Scanner**: Basic device discovery
- 📊 **Vendor Detection**: MAC address analysis
- 💾 **JSON Storage**: Structured data format

---

## 🤝 **Đóng Góp**

Chúng tôi hoan nghênh mọi đóng góp! Vui lòng:

1. **Fork** repository
2. **Tạo branch** mới (`git checkout -b feature/AmazingFeature`)
3. **Commit** thay đổi (`git commit -m 'Add AmazingFeature'`)
4. **Push** lên branch (`git push origin feature/AmazingFeature`)
5. **Tạo Pull Request**

---

## 📄 **License**

**MIT License** - Xem file [LICENSE](LICENSE) để biết chi tiết.

```
Copyright (c) 2024 NetScanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## ⚠️ **Disclaimer**

**Công cụ này được tạo ra chỉ cho mục đích giáo dục và nghiên cứu bảo mật mạng. Tác giả không chịu trách nhiệm về bất kỳ việc sử dụng sai mục đích nào. Người dùng phải tuân thủ luật pháp địa phương và chỉ sử dụng trên các mạng mà họ có quyền truy cập.**

---

<div align="center">

**🔒 Sử dụng có trách nhiệm - Học tập an toàn**

*Made with ❤️ for educational purposes*

</div>
