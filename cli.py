#!/usr/bin/env python3
"""
NetScanner CLI - Giao diện dòng lệnh tương tác cho NetScanner
"""

import os
import sys
import time
import logging
import readline
from core import NetScannerCore
import subprocess
import socket
from colorama import Fore, Style, init

# Khởi tạo colorama
init()

def print_banner():
    """Hiển thị banner của ứng dụng"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════╗
║ {Fore.GREEN}NETSCANNER{Fore.RED} - Advanced Network Discovery Tool              ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def print_help():
    """Hiển thị menu trợ giúp"""
    help_text = f"""
{Fore.YELLOW}Các lệnh có sẵn:{Style.RESET_ALL}

{Fore.CYAN}Quét mạng:{Style.RESET_ALL}
  {Fore.GREEN}scan{Style.RESET_ALL}                  - Quét nhanh các thiết bị trong mạng LAN
  {Fore.GREEN}scan -v{Style.RESET_ALL}                - Quét chi tiết (loại thiết bị + hệ điều hành)
  {Fore.GREEN}scan -vv{Style.RESET_ALL}               - Quét nâng cao (OS + Services + Security + Latency)

{Fore.CYAN}Tấn công (Mục đích giáo dục):{Style.RESET_ALL}
  {Fore.YELLOW}!!! CẢNH BÁO: Chỉ sử dụng trên mạng được cho phép !!!{Style.RESET_ALL}
  {Fore.GREEN}ddos{Style.RESET_ALL}                  - Tấn công DDoS với menu lựa chọn
  {Fore.GREEN}ddos --port <cổng>{Style.RESET_ALL}     - Tấn công vào một cổng cụ thể (mặc định: 80)
  {Fore.GREEN}ddos --no-spoof{Style.RESET_ALL}        - Tấn công không giả mạo IP nguồn
  {Fore.GREEN}ddos --skip-ping{Style.RESET_ALL}       - Bỏ qua kiểm tra ping trước khi tấn công
  {Fore.GREEN}mitm{Style.RESET_ALL}                   - Tấn công Man-in-the-Middle (một hoặc nhiều mục tiêu)
  {Fore.RED}mitb{Style.RESET_ALL}                   - Tấn công Man-in-the-Browser (Mô phỏng, yêu cầu MitM)

{Fore.CYAN}Phân tích mạng:{Style.RESET_ALL}
  {Fore.GREEN}sniff{Style.RESET_ALL}                 - Nghe lén gói tin (chế độ Thụ động/Chủ động)
  {Fore.GREEN}sniff --filter "port 80"{Style.RESET_ALL} - Nghe lén với bộ lọc BPF (Berkeley Packet Filter)
  {Fore.GREEN}sniff --save <file.pcap>{Style.RESET_ALL} - Lưu kết quả ra file PCAP để phân tích bằng Wireshark

{Fore.CYAN}Khác:{Style.RESET_ALL}
  {Fore.GREEN}clean{Style.RESET_ALL}                 - Dọn dẹp file log và devices.txt
  {Fore.GREEN}reap{Style.RESET_ALL}                  - Dọn dẹp các tiến trình "zombie" (nếu có)
  {Fore.GREEN}help{Style.RESET_ALL}                  - Hiển thị menu trợ giúp này
  {Fore.GREEN}exit{Style.RESET_ALL}                  - Thoát khỏi chương trình
"""
    print(help_text)

def setup_global_logging(debug=False):
    """Cấu hình logging tập trung cho toàn bộ ứng dụng."""
    log_level = logging.DEBUG if debug else logging.INFO
    log_file = 'logs/netscanner.log'

    # Lấy root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Xóa các handler cũ để tránh log bị nhân đôi
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Định dạng log, thêm %(name)s để biết log từ module nào
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Thêm handler cho file và console
    root_logger.addHandler(logging.FileHandler(log_file))
    root_logger.addHandler(logging.StreamHandler(sys.stdout))

def get_python_interpreter():
    """Lấy đường dẫn đến Python interpreter"""
    venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin", "python")
    if os.path.exists(venv_python):
        return venv_python
    return "python3"

def get_local_ip():
    """Lấy địa chỉ IP local"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def show_network_info():
    """Hiển thị thông tin mạng và cho phép chọn interface."""
    try:
        import netifaces
        
        print(f"\n{Fore.CYAN}=== THÔNG TIN MẠNG ==={Style.RESET_ALL}")
        
        interfaces = []
        for iface in netifaces.interfaces():
            if iface != 'lo':  # Bỏ qua loopback
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        interfaces.append({
                            'name': iface,
                            'ip': ip_info['addr'],
                            'netmask': ip_info['netmask']
                        })
                except:
                    continue
        
        if not interfaces:
            print(f"{Fore.RED}Không tìm thấy interface mạng nào có IP.{Style.RESET_ALL}")
            return None
            
        print(f"{'STT':<4} {'Interface':<12} {'IP Address':<15} {'Netmask':<15}")
        print("-" * 50)
        
        for i, iface in enumerate(interfaces, 1):
            print(f"{i:<4} {iface['name']:<12} {iface['ip']:<15} {iface['netmask']:<15}")
        
        while True:
            try:
                choice = input(f"\nChọn interface (1-{len(interfaces)}) hoặc Enter để tự động: ")
                if not choice.strip():
                    return get_interface()
                    
                choice = int(choice)
                if 1 <= choice <= len(interfaces):
                    selected = interfaces[choice - 1]['name']
                    print(f"{Fore.GREEN}Đã chọn interface: {selected}{Style.RESET_ALL}")
                    return selected
                else:
                    print(f"{Fore.RED}Lựa chọn không hợp lệ.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Vui lòng nhập số.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                return None
                
    except ImportError:
        print(f"{Fore.YELLOW}Không thể import netifaces. Sử dụng interface mặc định.{Style.RESET_ALL}")
        return get_interface()
    except Exception as e:
        print(f"{Fore.RED}Lỗi khi lấy thông tin mạng: {e}{Style.RESET_ALL}")
        return get_interface()

def get_interface():
    """Lấy interface mạng mặc định."""
    try:
        # Thử các interface phổ biến
        interfaces = ['eth0', 'wlan0', 'en0', 'enp0s3', 'ens33', 'enp0s8']
        
        # Kiểm tra interface nào tồn tại và có IP
        for iface in interfaces:
            if os.path.exists(f"/sys/class/net/{iface}"):
                # Kiểm tra xem interface có IP không
                try:
                    import netifaces
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        return iface
                except:
                    # Fallback: kiểm tra bằng ip command
                    try:
                        result = subprocess.run(['ip', 'addr', 'show', iface], 
                                              capture_output=True, text=True, timeout=2)
                        if 'inet ' in result.stdout:
                            return iface
                    except:
                        continue
        
        # Nếu không tìm thấy, thử lấy interface đầu tiên có IP
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface != 'lo':  # Bỏ qua loopback
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        return iface
        except:
            pass
            
        # Fallback cuối cùng
        return "eth0"
    except:
        return "eth0"

def execute_command(command, core):
    """Thực thi lệnh và hiển thị kết quả"""
    try:
        parts = command.split()
        base_command = parts[0]

        if base_command == "scan":
            # Phân tích các tùy chọn
            lookup_vendor = "-v" in command
            enhanced_scan = "-vv" in command or "--enhanced" in command
            core.scan_network(lookup_vendor=lookup_vendor, enhanced_scan=enhanced_scan)
            if core.scanner:
                core.scanner.print_results(detailed=enhanced_scan)

        elif base_command == "ddos":
            # Phân tích các tùy chọn cho ddos
            kwargs = {
                'port': 80,
                'spoof_ip': True,
                'debug': False,
                'skip_ping_check': False,
                'threads_per_target': 15,
                'packet_rate': 8000
            }

            if "--port" in parts:
                try:
                    port_index = parts.index("--port") + 1
                    kwargs['port'] = int(parts[port_index])
                except (ValueError, IndexError):
                    print(f"{Fore.RED}[!] Cú pháp --port không hợp lệ. Sử dụng: ddos --port <số cổng>{Style.RESET_ALL}")
                    return

            if "--no-spoof" in parts:
                kwargs['spoof_ip'] = False
            if "--debug" in parts:
                kwargs['debug'] = True
                # Cấu hình lại logging ở level DEBUG
                print(f"{Fore.MAGENTA}[*] Đã bật chế độ DEBUG. Logging sẽ chi tiết hơn.{Style.RESET_ALL}")
                setup_global_logging(debug=True)
            if "--skip-ping" in parts:
                kwargs['skip_ping_check'] = True

            print(f"{Fore.YELLOW}[!] CẢNH BÁO: Tấn công DDoS chỉ dành cho mục đích giáo dục.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Chuẩn bị tấn công DDoS... (Cổng: {kwargs['port']}, Giả mạo IP: {kwargs['spoof_ip']}){Style.RESET_ALL}")

            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return

            attacker_ip = get_local_ip()
            core.run_ddos(interface, attacker_ip, **kwargs)

        elif base_command == "mitm":
            print(f"{Fore.YELLOW}[!] CẢNH BÁO: Tấn công MitM sẽ làm gián đoạn và có thể giám sát lưu lượng mạng.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Đảm bảo bạn có toàn quyền trên mạng này.{Style.RESET_ALL}")

            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return

            kwargs = {
                'enable_sniffing': True,
                'poison_interval': 2,
            }
            core.run_mitm(interface, **kwargs)

        elif base_command == "mitb":
            print(f"{Fore.RED}[!] CẢNH BÁO: Tấn công Man-in-the-Browser (Mô phỏng) sẽ tiêm mã độc (JavaScript)")
            print(f"{Fore.RED}[!] vào các trang web mà nạn nhân truy cập để đánh cắp thông tin.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Kỹ thuật này yêu cầu giải mã SSL/TLS và nạn nhân phải cài đặt chứng chỉ CA.{Style.RESET_ALL}")

            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return

            kwargs = {
                # Các tùy chọn sẽ được xử lý trong module mitb
            }
            core.run_mitb(interface, **kwargs)

        elif base_command == "sniff":
            print(f"{Fore.CYAN}[*] Chuẩn bị khởi động module nghe lén...{Style.RESET_ALL}")
            
            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return

            kwargs = {}
            if "--filter" in parts:
                try:
                    filter_index = parts.index("--filter") + 1
                    # Ghép các phần của filter lại nếu nó chứa khoảng trắng và dấu ngoặc kép
                    filter_parts = []
                    for part in parts[filter_index:]:
                        if part.startswith('--'):
                            break
                        filter_parts.append(part)
                    kwargs['filter'] = " ".join(filter_parts).strip('"').strip("'")
                except IndexError:
                    print(f"{Fore.RED}[!] Cú pháp --filter không hợp lệ. Sử dụng: sniff --filter \"<bpf_filter>\"{Style.RESET_ALL}")
                    return
            
            if "--save" in parts:
                try:
                    save_index = parts.index("--save") + 1
                    kwargs['save_pcap'] = parts[save_index]
                except IndexError:
                    print(f"{Fore.RED}[!] Cú pháp --save không hợp lệ. Sử dụng: sniff --save <filename.pcap>{Style.RESET_ALL}")
                    return

            core.run_sniffer(interface, **kwargs)

        elif base_command == "clean":
            print(f"{Fore.CYAN}[*] Đang dọn dẹp các file log và cache...{Style.RESET_ALL}")

            # Các file và pattern cần dọn dẹp
            patterns_to_clean = [
                'devices.yaml',
                'devices.txt',
                #'logs/netscanner.log'  # Dọn dẹp file log tập trung
                'logs/*.log',  # Dọn dẹp tất cả file log trong thư mục logs
            ]

            cleaned_count = 0
            import glob
            for pattern in patterns_to_clean:
                try:
                    # Sử dụng glob để xử lý cả file đơn và pattern
                    files_to_remove = glob.glob(pattern)
                    if not files_to_remove:
                        continue

                    for file_path in files_to_remove:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            print(f"{Fore.GREEN}[+] Đã xóa: {file_path}{Style.RESET_ALL}")
                            cleaned_count += 1
                except Exception as e:
                    print(f"{Fore.RED}[!] Lỗi khi dọn dẹp pattern '{pattern}': {e}{Style.RESET_ALL}")

            if cleaned_count == 0:
                print(f"{Fore.YELLOW}[*] Không có file nào để dọn dẹp.{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Đã dọn dẹp {cleaned_count} file.{Style.RESET_ALL}")

        elif base_command == "reap":
            print(f"{Fore.CYAN}[*] Đang tìm và dọn dẹp các tiến trình zombie...{Style.RESET_ALL}")
            try:
                import psutil
                current_process = psutil.Process(os.getpid())
                children = current_process.children(recursive=True)
                zombies_found = 0
                for child in children:
                    if child.status() == psutil.STATUS_ZOMBIE:
                        print(f"{Fore.YELLOW}[!] Tìm thấy tiến trình zombie: PID {child.pid}, Tên: {child.name()}{Style.RESET_ALL}")
                        child.wait(timeout=0) # Dọn dẹp zombie
                        print(f"{Fore.GREEN}[+] Đã dọn dẹp zombie PID {child.pid}{Style.RESET_ALL}")
                        zombies_found += 1
                
                if zombies_found == 0:
                    print(f"{Fore.GREEN}[*] Không tìm thấy tiến trình zombie nào.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Đã dọn dẹp thành công {zombies_found} tiến trình zombie.{Style.RESET_ALL}")

            except ImportError:
                print(f"{Fore.RED}[!] Lỗi: Cần cài đặt thư viện 'psutil'. Vui lòng chạy: pip install psutil{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Lỗi khi dọn dẹp zombie: {e}{Style.RESET_ALL}")

        elif base_command == "help":
            print_help()
            
        elif base_command == "exit":
            print(f"{Fore.GREEN}[+] Tạm biệt!{Style.RESET_ALL}")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}[!] Lệnh không hợp lệ. Gõ 'help' để xem danh sách lệnh.{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Lỗi: {str(e)}{Style.RESET_ALL}")

def main():
    """Hàm chính của chương trình"""
    # Kiểm tra quyền root cho network scanning
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Chương trình cần quyền root để quét mạng.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Vui lòng chạy lại với sudo.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Cấu hình logging ngay khi bắt đầu
    setup_global_logging()

    print_banner()
    print(f"{Fore.YELLOW}Nhập 'help' để xem danh sách lệnh.{Style.RESET_ALL}")

    # Khởi tạo core một lần duy nhất
    core = NetScannerCore()

    # Vòng lặp chính
    while True:
        try:
            command = input(f"{Fore.GREEN}netscanner> {Style.RESET_ALL}")
            if command.strip():
                execute_command(command.strip(), core)
        except KeyboardInterrupt:
            print("\n" + f"{Fore.GREEN}[+] Tạm biệt!{Style.RESET_ALL}")
            break

if __name__ == "__main__":
    main()