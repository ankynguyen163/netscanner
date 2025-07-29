#!/usr/bin/env python3
"""
Network Scanner Module - Enhanced Version
Quét mạng và phát hiện thiết bị với thông tin chi tiết
"""

import os
import sys
import socket
import nmap
import yaml
import json
import time
import subprocess
import platform
from datetime import datetime
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class NetworkScanner:
    """
    Module quét mạng và phát hiện thiết bị nâng cao
    """
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.devices = {}
        self.device_db_file = "devices.yaml"  # Chuyển sang YAML
        self.scan_history = []
        
        # Lock for thread-safe updates to shared structures
        self.lock = threading.Lock()
        self.max_workers = min(32, (os.cpu_count() or 1) * 4)
        
        # Tạo thư mục logs nếu chưa có
        os.makedirs('logs', exist_ok=True)
        
        # Tải cơ sở dữ liệu thiết bị nếu có
        self.load_device_db()
    
    def get_network_info(self) -> Dict:
        """Lấy thông tin mạng chi tiết"""
        try:
            # Lấy thông tin interface chính
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Lấy thông tin gateway
            gateway = None
            try:
                if platform.system() == "Linux":
                    result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        gateway = result.stdout.split()[2]
                else:
                    result = subprocess.run(['netstat', '-nr'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'default' in line or '0.0.0.0' in line:
                                gateway = line.split()[1]
                                break
            except:
                pass
            
            # Lấy thông tin DNS
            dns_servers = []
            try:
                if platform.system() == "Linux":
                    with open('/etc/resolv.conf', 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_servers.append(line.split()[1])
                else:
                    result = subprocess.run(['nslookup', 'google.com'], 
                                          capture_output=True, text=True)
                    # Parse DNS servers from output
                    pass
            except:
                pass
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'gateway': gateway,
                'dns_servers': dns_servers,
                'network': '.'.join(local_ip.split('.')[:3]) + '.0/24',
                'scan_time': datetime.now().isoformat(),
                'platform': platform.system(),
                'python_version': platform.python_version()
            }
        except Exception as e:
            print(f"[-] Lỗi khi lấy thông tin mạng: {e}")
            return {}
    
    def scan(self, lookup_vendor=False, enhanced_scan=False):
        """Quét mạng để tìm thiết bị với thông tin nâng cao"""
        # Lấy thông tin mạng
        network_info = self.get_network_info()
        network = network_info.get('network', '192.168.1.0/24')
        
        print(f"[*] Đang quét mạng {network}...")
        print(f"[*] Local IP: {network_info.get('local_ip', 'Unknown')}")
        print(f"[*] Gateway: {network_info.get('gateway', 'Unknown')}")
        
        # Quét nhanh để tìm các thiết bị đang hoạt động
        scan_start = time.time()
        # Dùng các tùy chọn nmap tối ưu tốc độ: –n (bỏ DNS), -T4 (tốc độ cao), --min-parallelism tăng song song
        self.nm.scan(hosts=network, arguments='-n -sn -T4 --max-retries 1 --min-parallelism 64')
        scan_duration = time.time() - scan_start
        
        # Lưu kết quả với thông tin chi tiết
        for host in self.nm.all_hosts():
            device_info = self._create_device_info(host, network_info, scan_duration)
            
            if host not in self.devices:
                self.devices[host] = device_info
            else:
                # Cập nhật thông tin hiện có
                self.devices[host].update(device_info)
                self.devices[host]['last_seen'] = datetime.now().isoformat()
                self.devices[host]['scan_count'] = self.devices[host].get('scan_count', 0) + 1
        
        # Nếu yêu cầu phân tích chi tiết
        if lookup_vendor or enhanced_scan:
            self.lookup_device_info(enhanced_scan)
        
        # Lưu lịch sử quét
        self.scan_history.append({
            'timestamp': datetime.now().isoformat(),
            'devices_found': len(self.devices),
            'scan_duration': scan_duration,
            'enhanced_scan': enhanced_scan
        })
        
        print(f"[+] Đã quét xong trong {scan_duration:.2f}s. Tìm thấy {len(self.devices)} thiết bị.")
        
        # Lưu cơ sở dữ liệu thiết bị
        self.save_device_db()
        
        return self.devices
    
    def _create_device_info(self, host: str, network_info: Dict, scan_duration: float) -> Dict:
        """Tạo thông tin thiết bị chi tiết"""
        try:
            host_info = self.nm[host]
            
            # Thông tin cơ bản
            device_info = {
                'ip_address': host,
                'hostname': host_info.hostname() if 'hostname' in host_info else '',
                'status': host_info['status']['state'],
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'scan_count': 1,
                'scan_duration': scan_duration,
                'network_info': network_info,
                
                # Thông tin MAC
                'mac_address': '',
                'vendor': '',
                'mac_vendor': '',
                
                # Thông tin hệ điều hành
                'os': '',
                'os_accuracy': 0,
                'os_family': '',
                'os_version': '',
                
                # Thông tin cổng
                'open_ports': [],
                'common_ports': {},
                'services': {},
                
                # Thông tin bảo mật
                'security_info': {
                    'firewall_detected': False,
                    'vulnerabilities': [],
                    'risk_level': 'low'
                },
                
                # Thông tin mạng
                'network_details': {
                    'latency': 0,
                    'bandwidth': 'unknown',
                    'connection_type': 'unknown'
                },
                
                # Metadata
                'device_type': 'unknown',
                'confidence': 0,
                'notes': ''
            }
            
            # Lấy thông tin MAC và vendor
            if 'addresses' in host_info and 'mac' in host_info['addresses']:
                device_info['mac_address'] = host_info['addresses']['mac']
                if 'vendor' in host_info and host_info['addresses']['mac'] in host_info['vendor']:
                    device_info['mac_vendor'] = host_info['vendor'][host_info['addresses']['mac']]
                    device_info['vendor'] = device_info['mac_vendor']
            
            # Xác định loại thiết bị dựa trên MAC
            device_info['device_type'] = self._detect_device_type(device_info['mac_address'], device_info['mac_vendor'])
            
            return device_info
            
        except Exception as e:
            print(f"[-] Lỗi khi tạo thông tin thiết bị {host}: {e}")
            return {
                'ip_address': host,
                'status': 'error',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def _detect_device_type(self, mac: str, vendor: str) -> str:
        """Xác định loại thiết bị dựa trên MAC và vendor"""
        if not mac:
            return 'unknown'
        
        mac_prefix = mac[:8].upper()
        vendor_lower = vendor.lower()
        
        # Router/Gateway
        if any(x in vendor_lower for x in ['router', 'gateway', 'tp-link', 'asus', 'netgear', 'linksys']):
            return 'router'
        
        # Mobile devices
        if any(x in vendor_lower for x in ['samsung', 'apple', 'xiaomi', 'huawei', 'oneplus', 'google']):
            return 'mobile'
        
        # Computers
        if any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'msi', 'intel', 'amd']):
            return 'computer'
        
        # IoT devices
        if any(x in vendor_lower for x in ['philips', 'nest', 'ring', 'amazon', 'google', 'smart']):
            return 'iot'
        
        # Network devices
        if any(x in vendor_lower for x in ['cisco', 'juniper', 'aruba', 'ruckus', 'ubiquiti']):
            return 'network_device'
        
        return 'unknown'
    
    def lookup_device_info(self, enhanced_scan=False):
        """Phân tích thêm thông tin về thiết bị"""
        print("[*] Đang phân tích thông tin thiết bị chi tiết (đa luồng)...")

        active_hosts = [host for host, info in self.devices.items() if info['status'] == 'up']
        total = len(active_hosts)

        # Hàm nội bộ để gọi kèm chỉ số tiến trình
        def _wrap_scan(index_host_tuple):
            idx, h = index_host_tuple
            return self._scan_single_host_detail(h, idx, total, enhanced_scan)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            list(executor.map(_wrap_scan, enumerate(active_hosts, 1)))

        # Sau khi hoàn thành tất cả, lưu cơ sở dữ liệu một lần để giảm I/O
        self.save_device_db()
    
    # === NEW: hàm quét chi tiết 1 host, dùng trong đa luồng ===
    def _scan_single_host_detail(self, host: str, idx: int, total: int, enhanced_scan: bool = False):
        """Quét chi tiết 1 host và cập nhật self.devices (thread-safe)"""
        try:
            print(f"[*] ({idx}/{total}) Đang quét {host} ...")

            ps = nmap.PortScanner()

            scan_args = '-n -T4 -sS -O --host-timeout 30s'
            if enhanced_scan:
                scan_args += ' -sV -sC --script=banner,http-title,ssl-cert'

            ps.scan(hosts=host, arguments=scan_args)

            device = self.devices.get(host, {})

            # Cập nhật thông tin OS
            if 'osmatch' in ps[host] and len(ps[host]['osmatch']) > 0:
                os_match = ps[host]['osmatch'][0]
                device['os'] = os_match['name']
                device['os_accuracy'] = os_match['accuracy']
                device['os_family'] = os_match.get('osfamily', '')
                device['os_version'] = os_match.get('osversion', '')

            # Cổng mở & dịch vụ
            if 'tcp' in ps[host]:
                device['open_ports'] = list(ps[host]['tcp'].keys())
                for port, service_info in ps[host]['tcp'].items():
                    if service_info['state'] == 'open':
                        device.setdefault('services', {})[port] = {
                            'name': service_info.get('name', ''),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }

            # -------- Phân tích bảo mật đơn giản --------
            security = device.setdefault('security_info', {
                'firewall_detected': False,
                'vulnerabilities': [],
                'risk_level': 'low'
            })

            if 'tcp' in ps[host]:
                filtered_ports = [p for p, inf in ps[host]['tcp'].items() if inf['state'] == 'filtered']
                if filtered_ports:
                    security['firewall_detected'] = True

            open_ports = device.get('open_ports', [])
            risk = []
            if 22 in open_ports:
                risk.append('SSH exposed')
            if 23 in open_ports:
                risk.append('Telnet exposed (high risk)')
            if 80 in open_ports:
                risk.append('HTTP exposed')
            if 443 in open_ports:
                risk.append('HTTPS exposed')
            if 445 in open_ports:
                risk.append('SMB exposed')
            security['vulnerabilities'] = risk
            if any('high risk' in r for r in risk):
                security['risk_level'] = 'high'
            elif len(risk) > 3:
                security['risk_level'] = 'medium'
            else:
                security['risk_level'] = 'low'

            # Đo độ trễ
            self._measure_latency(host)

            with self.lock:
                self.devices[host] = device

            print(f"[+] {host}: {device.get('mac_vendor', '')} | {device.get('os', '')} | {device.get('device_type', '')}")

        except Exception as e:
            print(f"[-] Lỗi khi quét {host}: {str(e)[:100]}...")
    
    def _analyze_security(self, host: str):
        """Phân tích thông tin bảo mật"""
        try:
            device = self.devices[host]
            
            # Kiểm tra firewall
            if 'tcp' in self.nm[host]:
                filtered_ports = [port for port, info in self.nm[host]['tcp'].items() 
                                if info['state'] == 'filtered']
                if filtered_ports:
                    device['security_info']['firewall_detected'] = True
            
            # Đánh giá mức độ rủi ro
            risk_factors = []
            
            # Cổng SSH mở
            if 22 in device.get('open_ports', []):
                risk_factors.append('SSH exposed')
            
            # Cổng Telnet mở
            if 23 in device.get('open_ports', []):
                risk_factors.append('Telnet exposed (high risk)')
            
            # Cổng HTTP mở
            if 80 in device.get('open_ports', []):
                risk_factors.append('HTTP exposed')
            
            # Cổng HTTP mở
            if 443 in device.get('open_ports', []):
                risk_factors.append('HTTPS exposed')
            
            # Cổng SMB mở
            if 445 in device.get('open_ports', []):
                risk_factors.append('SMB exposed')
            
            device['security_info']['vulnerabilities'] = risk_factors
            
            # Xác định mức độ rủi ro
            if any('high risk' in factor for factor in risk_factors):
                device['security_info']['risk_level'] = 'high'
            elif len(risk_factors) > 3:
                device['security_info']['risk_level'] = 'medium'
            else:
                device['security_info']['risk_level'] = 'low'
                
        except Exception as e:
            print(f"[-] Lỗi khi phân tích bảo mật {host}: {e}")
    
    def _measure_latency(self, host: str):
        """Đo độ trễ đến thiết bị"""
        try:
            import subprocess
            result = subprocess.run(['ping', '-c', '1', '-W', '1', host], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse ping output để lấy thời gian trung bình
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'avg' in line:
                        try:
                            avg_time = float(line.split('/')[-3])
                            self.devices[host]['network_details']['latency'] = avg_time
                            break
                        except:
                            pass
        except:
            pass
    
    def load_device_db(self):
        """Tải cơ sở dữ liệu thiết bị từ file YAML"""
        try:
            if os.path.exists(self.device_db_file):
                with open(self.device_db_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data:
                        self.devices = data.get('devices', {})
                        self.scan_history = data.get('scan_history', [])
        except Exception as e:
            print(f"[-] Lỗi khi tải cơ sở dữ liệu thiết bị: {e}")
            # Fallback to JSON if YAML fails
            try:
                json_file = self.device_db_file.replace('.yaml', '.txt')
                if os.path.exists(json_file):
                    with open(json_file, 'r') as f:
                        self.devices = json.load(f)
            except:
                pass
    
    def save_device_db(self):
        """Lưu cơ sở dữ liệu thiết bị vào file YAML"""
        try:
            data = {
                'metadata': {
                    'created': datetime.now().isoformat(),
                    'total_devices': len(self.devices),
                    'version': '2.0.0'
                },
                'devices': self.devices,
                'scan_history': self.scan_history[-10:]  # Lưu 10 lần quét gần nhất
            }
            
            with open(self.device_db_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, indent=2)
        except Exception as e:
            print(f"[-] Lỗi khi lưu cơ sở dữ liệu: {e}")
    
    def print_results(self, detailed=False):
        """In kết quả quét ra màn hình với định dạng đẹp"""
        print("\n" + "="*80)
        print("🔍 KẾT QUẢ QUÉT MẠNG CHI TIẾT")
        print("="*80)
        
        # Thống kê tổng quan
        total_devices = len(self.devices)
        online_devices = len([d for d in self.devices.values() if d['status'] == 'up'])
        
        print(f"📊 THỐNG KÊ:")
        print(f"   • Tổng thiết bị: {total_devices}")
        print(f"   • Thiết bị online: {online_devices}")
        print(f"   • Thiết bị offline: {total_devices - online_devices}")
        
        # Phân loại thiết bị
        device_types = {}
        for device in self.devices.values():
            device_type = device.get('device_type', 'unknown')
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        print(f"\n📱 PHÂN LOẠI THIẾT BỊ:")
        for device_type, count in device_types.items():
            print(f"   • {device_type.title()}: {count}")
        
        # Bảng thiết bị chi tiết
        print(f"\n🖥️ CHI TIẾT THIẾT BỊ:")
        print("-" * 120)
        print(f"{'IP Address':<15} {'Hostname':<20} {'MAC':<17} {'Vendor':<20} {'OS':<25} {'Type':<12} {'Risk':<6}")
        print("-" * 120)
        
        for host, info in sorted(self.devices.items()):
            if info['status'] == 'up':
                hostname = info.get('hostname', '')[:19]
                mac = info.get('mac_address', '')[:16]
                vendor = info.get('mac_vendor', '')[:19]
                os = info.get('os', '')[:24]
                device_type = info.get('device_type', 'unknown')[:11]
                risk = info.get('security_info', {}).get('risk_level', 'low')[:5]
                
                print(f"{host:<15} {hostname:<20} {mac:<17} {vendor:<20} {os:<25} {device_type:<12} {risk:<6}")
        
        print("-" * 120)
        
        # Thông tin bảo mật
        if detailed:
            print(f"\n🛡️ THÔNG TIN BẢO MẬT:")
            for host, info in self.devices.items():
                if info['status'] == 'up' and info.get('security_info', {}).get('vulnerabilities'):
                    print(f"\n📍 {host}:")
                    for vuln in info['security_info']['vulnerabilities']:
                        print(f"   ⚠️  {vuln}")
        
        # Lưu ý
        print(f"\n💡 LƯU Ý:")
        print(f"   • Kết quả đã được lưu vào: {self.device_db_file}")
        print(f"   • Sử dụng 'scan -v' để quét chi tiết hơn")
        print(f"   • Sử dụng 'clean' để dọn dẹp logs")
        print("="*80)
    
    def reset_device_db(self):
        """Xóa cơ sở dữ liệu thiết bị"""
        self.devices = {}
        self.scan_history = []
        if os.path.exists(self.device_db_file):
            os.remove(self.device_db_file)
        print("[+] Đã xóa cơ sở dữ liệu thiết bị.")

# Hàm tiện ích để sử dụng trực tiếp
def scan_network(lookup_vendor=False, enhanced_scan=False):
    """Hàm tiện ích để quét mạng"""
    scanner = NetworkScanner()
    devices = scanner.scan(lookup_vendor, enhanced_scan)
    scanner.print_results(detailed=enhanced_scan)
    return devices

# Kiểm tra nếu script được chạy trực tiếp
if __name__ == "__main__":
    scan_network(True, True)