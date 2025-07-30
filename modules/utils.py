#!/usr/bin/env python3
"""
Utility Module - Chứa các hàm dùng chung cho các module khác.
"""

import os
import json
import yaml
from typing import Dict, List

def load_device_database(logger) -> Dict:
    """
    Tải cơ sở dữ liệu thiết bị từ file YAML hoặc JSON.
    
    :param logger: Đối tượng logger để ghi log.
    :return: Một dictionary chứa thông tin các thiết bị.
    """
    devices = {}
    try:
        yaml_file = 'devices.yaml'
        if os.path.exists(yaml_file):
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and 'devices' in data:
                    return data.get('devices', {}) # Trả về dict rỗng nếu không có
    except Exception as e:
        logger.warning(f"Không thể tải DB thiết bị, sẽ dựa vào ARP requests: {e}")
    return devices

def load_targets_from_scan(logger, attacker_ip: str, exclude_router: bool = True, exclude_attacker: bool = True) -> List[str]:
    """
    Tải danh sách mục tiêu từ kết quả quét mạng.
    
    :param logger: Đối tượng logger để ghi log.
    :param attacker_ip: IP của máy tấn công để loại trừ.
    :param exclude_router: Loại trừ IP router (thường là .1).
    :param exclude_attacker: Loại trừ IP của attacker.
    :return: Danh sách IP mục tiêu.
    """
    targets = []
    
    try:
        devices = load_device_database(logger)
        if not devices:
            logger.warning("Không tìm thấy file devices.yaml hoặc devices.txt. Vui lòng quét mạng trước.")
            return targets
            
        for ip, info in devices.items():
            if info.get('status') == 'up':
                # Loại trừ router (thường là .1)
                if exclude_router and (ip.endswith('.1') or info.get('device_type') == 'router'):
                    logger.info(f"Loại trừ router: {ip}")
                    continue
                    
                # Loại trừ attacker
                if exclude_attacker and ip == attacker_ip:
                    logger.info(f"Loại trừ attacker: {ip}")
                    continue
                    
                targets.append(ip)
                
        logger.info(f"Đã tải {len(targets)} mục tiêu từ cơ sở dữ liệu thiết bị.")
            
    except Exception as e:
        logger.error(f"Lỗi khi tải targets: {e}")
        
    return targets