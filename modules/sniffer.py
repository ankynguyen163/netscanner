#!/usr/bin/env python3
"""
Network Sniffer Module - Advanced Version
Bắt và phân tích gói tin mạng với khả năng deep packet inspection
*** CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU. ***
"""

import threading
import time
import os
import socket
import struct
import logging
import json
import re
import base64
import gzip
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import hashlib

# Scapy imports
from scapy.all import (
    sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6, 
    ARP, DNS, DHCP, Raw, Padding, get_if_list
)

# Protocol constants
PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP', 
    17: 'UDP',
    58: 'ICMPv6'
}

COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    6379: 'Redis', 27017: 'MongoDB'
}

class PacketAnalyzer:
    """Phân tích chi tiết gói tin"""
    
    @staticmethod
    def extract_http_data(packet) -> Dict:
        """Trích xuất dữ liệu HTTP"""
        try:
            if not packet.haslayer(Raw):
                return {}
            
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # HTTP Request
            if raw_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                lines = raw_data.split('\n')
                request_line = lines[0].strip()
                method, path, version = request_line.split(' ', 2)
                
                headers = {}
                body = ""
                body_started = False
                
                for line in lines[1:]:
                    if not body_started:
                        if line.strip() == '':
                            body_started = True
                            continue
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
                    else:
                        body += line + '\n'
                
                return {
                    'type': 'request',
                    'method': method,
                    'path': path,
                    'version': version,
                    'headers': headers,
                    'body': body.strip(),
                    'host': headers.get('host', ''),
                    'user_agent': headers.get('user-agent', ''),
                    'cookies': headers.get('cookie', ''),
                    'authorization': headers.get('authorization', '')
                }
            
            # HTTP Response
            elif raw_data.startswith('HTTP/'):
                lines = raw_data.split('\n')
                status_line = lines[0].strip()
                version, status_code, status_text = status_line.split(' ', 2)
                
                headers = {}
                body = ""
                body_started = False
                
                for line in lines[1:]:
                    if not body_started:
                        if line.strip() == '':
                            body_started = True
                            continue
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
                    else:
                        body += line + '\n'
                
                return {
                    'type': 'response',
                    'version': version,
                    'status_code': status_code,
                    'status_text': status_text,
                    'headers': headers,
                    'body': body.strip(),
                    'content_type': headers.get('content-type', ''),
                    'content_length': headers.get('content-length', ''),
                    'server': headers.get('server', '')
                }
                
        except Exception as e:
            logging.debug(f"Lỗi khi phân tích HTTP: {e}")
        
        return {}
    
    @staticmethod
    def extract_credentials(packet) -> List[Dict]:
        """Trích xuất thông tin xác thực"""
        credentials = []
        
        try:
            if not packet.haslayer(Raw):
                return credentials
            
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # HTTP Basic Auth
            auth_match = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', raw_data)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        credentials.append({
                            'type': 'HTTP Basic Auth',
                            'username': username,
                            'password': password,
                            'source': f"{packet[IP].src}:{packet[TCP].sport}",
                            'destination': f"{packet[IP].dst}:{packet[TCP].dport}"
                        })
                except:
                    pass
            
            # Form-based authentication
            if 'POST' in raw_data and 'application/x-www-form-urlencoded' in raw_data:
                # Extract form data
                form_patterns = [
                    r'username=([^&\s]+)',
                    r'user=([^&\s]+)',
                    r'login=([^&\s]+)',
                    r'email=([^&\s]+)'
                ]
                pass_patterns = [
                    r'password=([^&\s]+)',
                    r'pass=([^&\s]+)',
                    r'passwd=([^&\s]+)'
                ]
                
                username = None
                password = None
                
                for pattern in form_patterns:
                    match = re.search(pattern, raw_data, re.IGNORECASE)
                    if match:
                        username = match.group(1)
                        break
                
                for pattern in pass_patterns:
                    match = re.search(pattern, raw_data, re.IGNORECASE)
                    if match:
                        password = match.group(1)
                        break
                
                if username and password:
                    credentials.append({
                        'type': 'Form-based Auth',
                        'username': username,
                        'password': password,
                        'source': f"{packet[IP].src}:{packet[TCP].sport}",
                        'destination': f"{packet[IP].dst}:{packet[TCP].dport}"
                    })
            
            # FTP credentials
            ftp_patterns = [
                r'USER\s+([^\r\n]+)',
                r'PASS\s+([^\r\n]+)'
            ]
            
            for pattern in ftp_patterns:
                match = re.search(pattern, raw_data, re.IGNORECASE)
                if match:
                    cred_type = 'FTP Username' if 'USER' in pattern else 'FTP Password'
                    credentials.append({
                        'type': cred_type,
                        'value': match.group(1).strip(),
                        'source': f"{packet[IP].src}:{packet[TCP].sport}",
                        'destination': f"{packet[IP].dst}:{packet[TCP].dport}"
                    })
            
        except Exception as e:
            logging.debug(f"Lỗi khi trích xuất credentials: {e}")
        
        return credentials
    
    @staticmethod
    def extract_dns_data(packet) -> Dict:
        """Trích xuất thông tin DNS"""
        try:
            if packet.haslayer(DNS):
                dns = packet[DNS]
                
                queries = []
                answers = []
                
                # DNS Queries
                if dns.qd:
                    for i in range(dns.qdcount):
                        if i < len(dns.qd):
                            query = dns.qd[i]
                            queries.append({
                                'name': query.qname.decode('utf-8', errors='ignore').rstrip('.'),
                                'type': query.qtype,
                                'class': query.qclass
                            })
                
                # DNS Answers
                if dns.an:
                    for i in range(dns.ancount):
                        if i < len(dns.an):
                            answer = dns.an[i]
                            answers.append({
                                'name': answer.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                                'type': answer.type,
                                'class': answer.rclass,
                                'ttl': answer.ttl,
                                'data': str(answer.rdata)
                            })
                
                return {
                    'id': dns.id,
                    'flags': dns.flags,
                    'queries': queries,
                    'answers': answers,
                    'query_type': 'query' if dns.qr == 0 else 'response'
                }
                
        except Exception as e:
            logging.debug(f"Lỗi khi phân tích DNS: {e}")
        
        return {}

class NetworkSniffer:
    """
    Advanced Network Sniffer với khả năng deep packet inspection
    """
    
    def __init__(self, interface: str = None, filter_expression: str = "",
                 capture_file: str = None, max_packets: int = 0,
                 enable_deep_inspection: bool = True, enable_credential_harvest: bool = True):
        """
        Khởi tạo Network Sniffer
        
        :param interface: Interface mạng để sniff (None = auto detect)
        :param filter_expression: BPF filter expression
        :param capture_file: File để lưu captured packets
        :param max_packets: Số lượng packet tối đa (0 = unlimited)
        :param enable_deep_inspection: Bật deep packet inspection
        :param enable_credential_harvest: Bật credential harvesting
        """
        self.interface = interface or self._get_default_interface()
        self.filter_expression = filter_expression
        self.capture_file = capture_file
        self.max_packets = max_packets
        self.enable_deep_inspection = enable_deep_inspection
        self.enable_credential_harvest = enable_credential_harvest
        
        # Packet storage and analysis
        self.captured_packets = deque(maxlen=10000)  # Giới hạn memory
        self.packet_count = 0
        self.start_time = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'hosts': defaultdict(int),
            'ports': defaultdict(int),
            'http_requests': 0,
            'dns_queries': 0,
            'credentials_found': 0,
            'data_volume': 0
        }
        
        # Deep inspection results
        self.http_sessions = {}
        self.dns_queries = []
        self.credentials = []
        self.file_transfers = []
        self.suspicious_activity = []
        
        # Threading control
        self.stop_event = threading.Event()
        self.threads = []
        self.stats_lock = threading.Lock()
        
        # Analyzer
        self.analyzer = PacketAnalyzer()
        
        # Setup logging
        self._setup_logging()
        
        self.logger.info(f"Network Sniffer khởi tạo trên interface: {self.interface}")
    
    def _setup_logging(self):
        """Thiết lập logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('sniffer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _get_default_interface(self) -> str:
        """Tự động phát hiện interface mạng chính"""
        try:
            interfaces = get_if_list()
            # Loại bỏ loopback và virtual interfaces
            valid_interfaces = [iface for iface in interfaces 
                             if not iface.startswith(('lo', 'veth', 'docker', 'br-'))]
            
            if valid_interfaces:
                return valid_interfaces[0]
            else:
                return 'eth0'  # fallback
        except:
            return 'eth0'
    
    def _packet_handler(self, packet):
        """Xử lý từng gói tin được bắt"""
        try:
            with self.stats_lock:
                self.packet_count += 1
                self.stats['total_packets'] += 1
                
                # Basic packet info
                packet_info = self._extract_basic_info(packet)
                
                # Deep packet inspection
                if self.enable_deep_inspection:
                    packet_info.update(self._deep_inspect_packet(packet))
                
                # Credential harvesting
                if self.enable_credential_harvest:
                    creds = self.analyzer.extract_credentials(packet)
                    if creds:
                        self.credentials.extend(creds)
                        self.stats['credentials_found'] += len(creds)
                        self.logger.warning(f"🔑 Tìm thấy {len(creds)} credentials!")
                
                # Store packet
                self.captured_packets.append({
                    'timestamp': datetime.now(),
                    'packet_num': self.packet_count,
                    'raw_packet': packet,
                    'info': packet_info
                })
                
                # Update statistics
                self._update_statistics(packet, packet_info)
                
                # Check for suspicious activity
                self._check_suspicious_activity(packet, packet_info)
                
                # Stop if max packets reached
                if self.max_packets > 0 and self.packet_count >= self.max_packets:
                    self.logger.info(f"Đã đạt giới hạn {self.max_packets} packets")
                    self.stop_sniffing()
                    
        except Exception as e:
            self.logger.error(f"Lỗi khi xử lý packet: {e}")
    
    def _extract_basic_info(self, packet) -> Dict:
        """Trích xuất thông tin cơ bản từ packet"""
        info = {
            'size': len(packet),
            'protocols': [],
            'src_ip': '',
            'dst_ip': '',
            'src_port': 0,
            'dst_port': 0,
            'protocol': '',
            'summary': str(packet.summary())
        }
        
        # Ethernet layer
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
            info['protocols'].append('Ethernet')
        
        # IP layer
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = PROTOCOLS.get(packet[IP].proto, str(packet[IP].proto))
            info['protocols'].append('IP')
            info['ttl'] = packet[IP].ttl
            info['ip_flags'] = packet[IP].flags
        
        # IPv6 layer
        elif packet.haslayer(IPv6):
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            info['protocols'].append('IPv6')
        
        # Transport layer
        if packet.haslayer(TCP):
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['protocols'].append('TCP')
            info['tcp_flags'] = packet[TCP].flags
            info['seq'] = packet[TCP].seq
            info['ack'] = packet[TCP].ack
            info['window'] = packet[TCP].window
            
            # Identify service
            service = COMMON_PORTS.get(packet[TCP].dport, 
                     COMMON_PORTS.get(packet[TCP].sport, 'Unknown'))
            info['service'] = service
            
        elif packet.haslayer(UDP):
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            info['protocols'].append('UDP')
            
            # Identify service
            service = COMMON_PORTS.get(packet[UDP].dport,
                     COMMON_PORTS.get(packet[UDP].sport, 'Unknown'))
            info['service'] = service
        
        # ICMP layer
        if packet.haslayer(ICMP):
            info['protocols'].append('ICMP')
            info['icmp_type'] = packet[ICMP].type
            info['icmp_code'] = packet[ICMP].code
        
        # ARP layer
        if packet.haslayer(ARP):
            info['protocols'].append('ARP')
            info['arp_op'] = packet[ARP].op
            info['arp_hwsrc'] = packet[ARP].hwsrc
            info['arp_hwdst'] = packet[ARP].hwdst
        
        return info
    
    def _deep_inspect_packet(self, packet) -> Dict:
        """Deep packet inspection"""
        deep_info = {}
        
        try:
            # HTTP Analysis
            if packet.haslayer(TCP) and packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080]:
                http_data = self.analyzer.extract_http_data(packet)
                if http_data:
                    deep_info['http'] = http_data
                    self.stats['http_requests'] += 1
                    
                    # Store HTTP session
                    session_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
                    if session_key not in self.http_sessions:
                        self.http_sessions[session_key] = []
                    self.http_sessions[session_key].append({
                        'timestamp': datetime.now(),
                        'data': http_data
                    })
            
            # HTTPS Detection
            if packet.haslayer(TCP) and packet[TCP].dport == 443 or packet[TCP].sport == 443:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # Check for TLS handshake
                    if len(payload) > 0 and payload[0] == 0x16:  # TLS Handshake
                        deep_info['tls'] = {
                            'type': 'handshake',
                            'version': f"{payload[1]}.{payload[2]}" if len(payload) > 2 else "unknown"
                        }
            
            # DNS Analysis
            if packet.haslayer(DNS):
                dns_data = self.analyzer.extract_dns_data(packet)
                if dns_data:
                    deep_info['dns'] = dns_data
                    self.dns_queries.append({
                        'timestamp': datetime.now(),
                        'src_ip': packet[IP].src,
                        'data': dns_data
                    })
                    self.stats['dns_queries'] += 1
            
            # DHCP Analysis
            if packet.haslayer(DHCP):
                dhcp_options = []
                for option in packet[DHCP].options:
                    if isinstance(option, tuple):
                        dhcp_options.append({
                            'code': option[0],
                            'value': str(option[1])
                        })
                
                deep_info['dhcp'] = {
                    'message_type': packet[DHCP].options[0][1] if packet[DHCP].options else 0,
                    'options': dhcp_options
                }
            
        except Exception as e:
            self.logger.debug(f"Lỗi trong deep inspection: {e}")
        
        return deep_info
    
    def _update_statistics(self, packet, packet_info: Dict):
        """Cập nhật thống kê"""
        try:
            # Protocol statistics
            for protocol in packet_info.get('protocols', []):
                self.stats['protocols'][protocol] += 1
            
            # Host statistics
            if packet_info.get('src_ip'):
                self.stats['hosts'][packet_info['src_ip']] += 1
            if packet_info.get('dst_ip'):
                self.stats['hosts'][packet_info['dst_ip']] += 1
            
            # Port statistics
            if packet_info.get('src_port'):
                self.stats['ports'][packet_info['src_port']] += 1
            if packet_info.get('dst_port'):
                self.stats['ports'][packet_info['dst_port']] += 1
            
            # Data volume
            self.stats['data_volume'] += packet_info.get('size', 0)
            
        except Exception as e:
            self.logger.debug(f"Lỗi khi cập nhật thống kê: {e}")
    
    def _check_suspicious_activity(self, packet, packet_info: Dict):
        """Kiểm tra hoạt động đáng nghi"""
        try:
            suspicious = []
            
            # Port scanning detection
            if packet_info.get('dst_port') and packet_info['dst_port'] > 1024:
                # Check if this IP is scanning many ports
                src_ip = packet_info.get('src_ip')
                if src_ip:
                    # Simple heuristic: if we see the same src_ip with many different dst_ports
                    pass  # Implement more sophisticated detection later
            
            # Unusual protocols
            if packet_info.get('protocol') not in ['TCP', 'UDP', 'ICMP']:
                suspicious.append(f"Unusual protocol: {packet_info['protocol']}")
            
            # Large packets
            if packet_info.get('size', 0) > 1500:
                suspicious.append(f"Large packet: {packet_info['size']} bytes")
            
            # Suspicious ports
            suspicious_ports = [23, 135, 139, 445, 1433, 3389]
            if packet_info.get('dst_port') in suspicious_ports:
                suspicious.append(f"Connection to suspicious port: {packet_info['dst_port']}")
            
            if suspicious:
                self.suspicious_activity.append({
                    'timestamp': datetime.now(),
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'alerts': suspicious,
                    'packet_info': packet_info
                })
                
        except Exception as e:
            self.logger.debug(f"Lỗi khi kiểm tra suspicious activity: {e}")
    
    def _monitor_stats(self):
        """Monitor và hiển thị thống kê real-time"""
        while not self.stop_event.is_set():
            time.sleep(10)  # Update every 10 seconds
            
            with self.stats_lock:
                if self.start_time:
                    elapsed = time.time() - self.start_time
                    pps = self.stats['total_packets'] / elapsed if elapsed > 0 else 0
                    
                    self.logger.info(
                        f"📊 Stats: {self.stats['total_packets']} packets, "
                        f"{pps:.1f} pps, {self.stats['data_volume'] / 1024 / 1024:.2f} MB, "
                        f"{len(self.credentials)} credentials, "
                        f"{len(self.suspicious_activity)} alerts"
                    )
    
    def start_sniffing(self) -> bool:
        """Bắt đầu sniffing"""
        try:
            self.logger.info(f"🚀 Bắt đầu sniffing trên {self.interface}")
            if self.filter_expression:
                self.logger.info(f"📝 Filter: {self.filter_expression}")
            
            self.start_time = time.time()
            self.stop_event.clear()
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitor_stats, daemon=True)
            monitor_thread.start()
            self.threads.append(monitor_thread)
            
            # Start sniffing (this blocks)
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self.filter_expression,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=0  # Don't store packets in memory (we handle that)
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi bắt đầu sniffing: {e}")
            return False
    
    def stop_sniffing(self):
        """Dừng sniffing"""
        self.logger.info("🛑 Đang dừng sniffing...")
        self.stop_event.set()
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        self.logger.info("✅ Đã dừng sniffing")
    
    def get_statistics(self) -> Dict:
        """Lấy thống kê chi tiết"""
        with self.stats_lock:
            stats = dict(self.stats)
            
            # Convert defaultdict to regular dict for JSON serialization
            stats['protocols'] = dict(stats['protocols'])
            stats['hosts'] = dict(stats['hosts'])
            stats['ports'] = dict(stats['ports'])
            
            # Add runtime info
            if self.start_time:
                stats['runtime'] = time.time() - self.start_time
                stats['pps'] = stats['total_packets'] / stats['runtime'] if stats['runtime'] > 0 else 0
            
            # Top talkers
            stats['top_hosts'] = sorted(stats['hosts'].items(), key=lambda x: x[1], reverse=True)[:10]
            stats['top_ports'] = sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]
            stats['top_protocols'] = sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]
            
            return stats
    
    def export_results(self, filename: str = None, format: str = 'json'):
        """Xuất kết quả ra file"""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"sniffer_results_{timestamp}.{format}"
            
            results = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'interface': self.interface,
                    'filter': self.filter_expression,
                    'runtime': time.time() - self.start_time if self.start_time else 0
                },
                'statistics': self.get_statistics(),
                'credentials': self.credentials,
                'http_sessions': {k: v for k, v in list(self.http_sessions.items())[:10]},  # Limit output
                'dns_queries': self.dns_queries[-100:],  # Last 100 DNS queries
                'suspicious_activity': self.suspicious_activity,
                'captured_packets_summary': len(self.captured_packets)
            }
            
            if format.lower() == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"💾 Đã xuất kết quả ra: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Lỗi khi xuất kết quả: {e}")
            return None
    
    def print_summary(self):
        """In tóm tắt kết quả"""
        stats = self.get_statistics()
        
        print("\n" + "="*80)
        print("🕵️ NETWORK SNIFFER SUMMARY")
        print("="*80)
        
        print(f"📊 THỐNG KÊ TỔNG QUAN:")
        print(f"   • Packets bắt được: {stats['total_packets']:,}")
        print(f"   • Dung lượng dữ liệu: {stats['data_volume'] / 1024 / 1024:.2f} MB")
        print(f"   • Thời gian chạy: {stats.get('runtime', 0):.1f}s")
        print(f"   • Tốc độ: {stats.get('pps', 0):.1f} packets/second")
        
        print(f"\n🌐 TOP PROTOCOLS:")
        for protocol, count in stats['top_protocols']:
            print(f"   • {protocol}: {count:,}")
        
        print(f"\n💻 TOP HOSTS:")
        for host, count in stats['top_hosts']:
            print(f"   • {host}: {count:,}")
        
        print(f"\n🚪 TOP PORTS:")
        for port, count in stats['top_ports']:
            service = COMMON_PORTS.get(port, 'Unknown')
            print(f"   • {port} ({service}): {count:,}")
        
        if self.credentials:
            print(f"\n🔑 CREDENTIALS HARVESTED ({len(self.credentials)}):")
            for i, cred in enumerate(self.credentials[:5], 1):  # Show first 5
                print(f"   {i}. {cred['type']}: {cred.get('username', 'N/A')} / {cred.get('password', cred.get('value', 'N/A'))}")
            if len(self.credentials) > 5:
                print(f"   ... và {len(self.credentials) - 5} credentials khác")
        
        if self.suspicious_activity:
            print(f"\n⚠️ SUSPICIOUS ACTIVITY ({len(self.suspicious_activity)}):")
            for i, activity in enumerate(self.suspicious_activity[:3], 1):  # Show first 3
                print(f"   {i}. {activity['src_ip']} -> {activity['dst_ip']}: {', '.join(activity['alerts'])}")
            if len(self.suspicious_activity) > 3:
                print(f"   ... và {len(self.suspicious_activity) - 3} alerts khác")
        
        print("="*80)

def run_network_sniffer(interface: str = None, **kwargs):
    """
    Hàm tiện ích để chạy network sniffer với giao diện đơn giản
    """
    print("\n=== NETWORK SNIFFER MODULE ===")
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("[-] CẢNH BÁO: Cần quyền root để bắt gói tin.")
        print("[-] Vui lòng chạy lại với sudo.")
        return
    
    # Configure sniffer
    filter_expr = kwargs.get('filter', '')
    max_packets = kwargs.get('max_packets', 0)
    
    # Menu for quick filters
    print("\n=== CHỌN BỘ LỌC ===")
    print("1. Tất cả traffic")
    print("2. Chỉ HTTP/HTTPS")
    print("3. Chỉ DNS")
    print("4. Chỉ TCP")
    print("5. Chỉ UDP")
    print("6. Bộ lọc tùy chỉnh")
    
    while True:
        try:
            choice = input("\nChọn bộ lọc (1-6): ")
            choice = int(choice)
            
            if choice == 1:
                filter_expr = ""
                print("[+] Sẽ bắt tất cả traffic")
                break
            elif choice == 2:
                filter_expr = "tcp port 80 or tcp port 443"
                print("[+] Sẽ bắt HTTP/HTTPS traffic")
                break
            elif choice == 3:
                filter_expr = "udp port 53"
                print("[+] Sẽ bắt DNS queries")
                break
            elif choice == 4:
                filter_expr = "tcp"
                print("[+] Sẽ bắt TCP traffic")
                break
            elif choice == 5:
                filter_expr = "udp"
                print("[+] Sẽ bắt UDP traffic")
                break
            elif choice == 6:
                filter_expr = input("Nhập BPF filter (ví dụ: 'host 192.168.1.1'): ")
                print(f"[+] Sẽ sử dụng filter: {filter_expr}")
                break
            else:
                print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
        except ValueError:
            print("Vui lòng nhập số.")
        except KeyboardInterrupt:
            return
    
    try:
        # Create and configure sniffer
        sniffer = NetworkSniffer(
            interface=interface,
            filter_expression=filter_expr,
            max_packets=max_packets,
            enable_deep_inspection=True,
            enable_credential_harvest=True
        )
        
        print(f"\n[+] Bắt đầu sniffing trên {sniffer.interface}")
        print("[+] Nhấn Ctrl+C để dừng...")
        
        # Start sniffing
        if sniffer.start_sniffing():
            try:
                # Keep running until interrupted
                while not sniffer.stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Người dùng yêu cầu dừng...")
        
        sniffer.stop_sniffing()
        
        # Show summary
        sniffer.print_summary()
        
        # Ask to export results
        export = input("\nBạn có muốn xuất kết quả ra file? (y/N): ")
        if export.lower() == 'y':
            filename = sniffer.export_results()
            if filename:
                print(f"[+] Kết quả đã được lưu vào: {filename}")
    
    except KeyboardInterrupt:
        print("\n[*] Hủy sniffing.")
    except Exception as e:
        print(f"[-] Lỗi: {e}")

if __name__ == "__main__":
    run_network_sniffer()