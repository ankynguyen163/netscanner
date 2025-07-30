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
from modules.ddos import run_ddos_attack as ddos_runner
from modules.mitm import run_mitm_attack as mitm_runner
from modules.mitb import run_mitb_attack as mitb_runner
from modules.sniffer import run_sniffer as sniffer_runner
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
    
    def run_ddos(self, interface, attacker_ip, **kwargs):
        """Chạy module DDoS với menu tương tác."""
        # Đảm bảo có kết quả quét trước
        if not os.path.exists('devices.yaml') and not os.path.exists('devices.txt'):
             print(f"[-] Không tìm thấy file kết quả quét (devices.yaml/devices.txt).")
             print(f"[-] Vui lòng chạy 'scan' trước khi tấn công.")
             return
        ddos_runner(attacker_ip=attacker_ip, interface=interface, **kwargs)

    def run_mitm(self, interface, **kwargs):
        """Chạy module MitM với menu tương tác."""
        # Đảm bảo có kết quả quét trước
        if not os.path.exists('devices.yaml') and not os.path.exists('devices.txt'):
             print(f"[-] Không tìm thấy file kết quả quét (devices.yaml/devices.txt).")
             print(f"[-] Vui lòng chạy 'scan' trước khi tấn công.")
             return
        mitm_runner(interface=interface, **kwargs)

    def run_mitb(self, interface, **kwargs):
        """Chạy module MitB với menu tương tác."""
        # Đảm bảo có kết quả quét trước
        if not os.path.exists('devices.yaml') and not os.path.exists('devices.txt'):
             print(f"[-] Không tìm thấy file kết quả quét (devices.yaml/devices.txt).")
             print(f"[-] Vui lòng chạy 'scan' trước khi tấn công.")
             return
        # Chạy runner từ module mitb.py
        mitb_runner(interface=interface, **kwargs)

    def run_sniffer(self, interface, **kwargs):
        """Chạy module Sniffer."""
        print("[*] Đang khởi chạy module Sniffer...")
        sniffer_runner(interface=interface, **kwargs)

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
