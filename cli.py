#!/usr/bin/env python3
"""
Parasite CLI - Giao diện dòng lệnh tương tác cho Parasite
"""

import os
import sys
import time
import readline
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
  {Fore.GREEN}ddos --debug{Style.RESET_ALL}           - Bật debug logging chi tiết
  {Fore.GREEN}ddos --skip-ping{Style.RESET_ALL}       - Bỏ qua kiểm tra ping trước khi tấn công
  {Fore.GREEN}mitm{Style.RESET_ALL}                   - Tấn công Man-in-the-Middle với menu lựa chọn

{Fore.CYAN}Khác:{Style.RESET_ALL}
  {Fore.GREEN}clean{Style.RESET_ALL}                 - Dọn dẹp file log và devices.txt
  {Fore.GREEN}help{Style.RESET_ALL}                  - Hiển thị menu trợ giúp này
  {Fore.GREEN}exit{Style.RESET_ALL}                  - Thoát khỏi chương trình
"""
    print(help_text)

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

def execute_command(command):
    """Thực thi lệnh và hiển thị kết quả"""
    try:
        if command.startswith("scan"):
            python_interpreter = get_python_interpreter()
            
            # Phân tích các tùy chọn
            lookup_vendor = "-v" in command
            enhanced_scan = "-vv" in command or "--enhanced" in command
            
            # Hiển thị thông báo phù hợp
            if enhanced_scan:
                print(f"{Fore.CYAN}[*] Đang quét nâng cao (OS + Services + Security + Latency)...{Style.RESET_ALL}")
            elif lookup_vendor:
                print(f"{Fore.CYAN}[*] Đang quét chi tiết (loại thiết bị + hệ điều hành)...{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] Đang quét nhanh các thiết bị trong mạng...{Style.RESET_ALL}")
            
            # Tạo script quét
            scan_script = """from core import NetScannerCore
scanner = NetScannerCore()
scanner.scan_network(lookup_vendor={lookup_vendor}, enhanced_scan={enhanced_scan})
scanner.scanner.print_results(detailed={enhanced_scan})
"""
            
            scan_script = scan_script.format(
                lookup_vendor=str(lookup_vendor),
                enhanced_scan=str(enhanced_scan)
            )
            
            subprocess.run([python_interpreter, "-c", scan_script])
            
        elif command.startswith("ddos"):
            python_interpreter = get_python_interpreter()
            
            # Phân tích các tùy chọn cho ddos
            parts = command.split()
            port = 80
            spoof_ip = True
            debug = False
            skip_ping = False
            
            if "--port" in parts:
                try:
                    port_index = parts.index("--port") + 1
                    if port_index < len(parts):
                        port = int(parts[port_index])
                    else:
                        raise ValueError
                except (ValueError, IndexError):
                    print(f"{Fore.RED}[!] Cú pháp --port không hợp lệ. Sử dụng: ddos --port <số cổng>{Style.RESET_ALL}")
                    return

            if "--no-spoof" in parts:
                spoof_ip = False
                
            if "--debug" in parts:
                debug = True
                
            if "--skip-ping" in parts:
                skip_ping = True

            print(f"{Fore.YELLOW}[!] CẢNH BÁO: Tấn công DDoS chỉ dành cho mục đích giáo dục.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Chuẩn bị tấn công DDoS... (Cổng: {port}, Giả mạo IP: {spoof_ip}){Style.RESET_ALL}")
            
            # Lấy thông tin mạng
            attacker_ip = get_local_ip()
            
            # Hiển thị thông tin mạng và cho phép chọn interface
            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return
            
            # Tạo script tấn công với menu lựa chọn
            attack_script = """
import time
from modules.ddos import run_ddos_attack

# Lấy thông tin mạng
attacker_ip = '{attacker_ip}'
interface = '{interface}'

# Chạy tấn công với menu lựa chọn
run_ddos_attack(
    attacker_ip=attacker_ip,
    interface=interface,
    port={port},
    spoof_ip={spoof_ip},
    threads_per_target=15,  # Tăng số luồng
    packet_rate=8000,       # Tăng tốc độ gửi
    debug={debug},
    skip_ping_check={skip_ping}
)
"""
            attack_script = attack_script.format(
                attacker_ip=attacker_ip,
                interface=interface,
                port=port,
                spoof_ip=str(spoof_ip),
                debug=str(debug),
                skip_ping=str(skip_ping)
            )
            subprocess.run([python_interpreter, "-c", attack_script])

        elif command.startswith("mitm"):
            python_interpreter = get_python_interpreter()

            print(f"{Fore.YELLOW}[!] CẢNH BÁO: Tấn công MitM sẽ làm gián đoạn và có thể giám sát lưu lượng mạng.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Đảm bảo bạn có toàn quyền trên mạng này.{Style.RESET_ALL}")

            # Hiển thị thông tin mạng và cho phép chọn interface
            interface = show_network_info()
            if not interface:
                print(f"{Fore.RED}[!] Không thể xác định interface mạng.{Style.RESET_ALL}")
                return

            # Tạo script tấn công với menu lựa chọn
            attack_script = """
import time
from modules.mitm import run_mitm_attack

# Lấy thông tin mạng
interface = '{interface}'

# Chạy tấn công với menu lựa chọn
run_mitm_attack(
    interface=interface,
    enable_sniffing=True,
    poison_interval=2
)
"""
            attack_script = attack_script.format(interface=interface)
            subprocess.run([python_interpreter, "-c", attack_script])

        elif command == "clean":
            print(f"{Fore.CYAN}[*] Đang dọn dẹp các file log và cache...{Style.RESET_ALL}")
            
            files_to_clean = [
                'devices.yaml',
                'devices.txt',
                'ddos_attack.log',
                'mitm_attack.log',
                'scanner.log',
                '*.log'
            ]
            
            cleaned_count = 0
            for file_pattern in files_to_clean:
                try:
                    if file_pattern == '*.log':
                        # Xóa tất cả file .log
                        import glob
                        for log_file in glob.glob('*.log'):
                            os.remove(log_file)
                            print(f"{Fore.GREEN}[+] Đã xóa: {log_file}{Style.RESET_ALL}")
                            cleaned_count += 1
                    else:
                        if os.path.exists(file_pattern):
                            os.remove(file_pattern)
                            print(f"{Fore.GREEN}[+] Đã xóa: {file_pattern}{Style.RESET_ALL}")
                            cleaned_count += 1
                except Exception as e:
                    print(f"{Fore.RED}[!] Lỗi khi xóa {file_pattern}: {e}{Style.RESET_ALL}")
            
            if cleaned_count == 0:
                print(f"{Fore.YELLOW}[*] Không có file nào để dọn dẹp.{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Đã dọn dẹp {cleaned_count} file.{Style.RESET_ALL}")

        elif command == "help":
            print_help()
            
        elif command == "exit":
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
    
    print_banner()
    print(f"{Fore.YELLOW}Nhập 'help' để xem danh sách lệnh.{Style.RESET_ALL}")
    
    # Vòng lặp chính
    while True:
        try:
            command = input(f"{Fore.GREEN}netscanner> {Style.RESET_ALL}")
            if command.strip():
                execute_command(command.strip())
        except KeyboardInterrupt:
            print("\n" + f"{Fore.GREEN}[+] Tạm biệt!{Style.RESET_ALL}")
            break

if __name__ == "__main__":
    main()