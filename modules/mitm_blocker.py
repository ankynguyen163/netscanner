"""
Mitmproxy Blocker Script - Chế độ "Bạo lực"
Chặn các kết nối đến các domain lớn được định nghĩa trước.
"""
from mitmproxy import http
from mitmproxy import ctx

# Danh sách các domain lớn cần chặn.
# Bất kỳ request nào có host chứa một trong các chuỗi này sẽ bị chặn.
BLOCKED_DOMAINS = [
    "google.com",
    "openai.com"
    "facebook.com",
    "youtube.com",
    "twitter.com",
    "instagram.com",
    "netflix.com",
    "amazon.com",
    "tiktok.com",
    "zalo.me",
    "bing.com"
]

class Blocker:
    def request(self, flow: http.HTTPFlow) -> None:
        """Hàm được gọi cho mỗi request."""
        if any(blocked_domain in flow.request.host for blocked_domain in BLOCKED_DOMAINS):
            ctx.log.warn(f"[VIOLENT MODE] Đã chặn request đến: {flow.request.host}")
            # "Giết" flow này, khiến trình duyệt của nạn nhân không thể kết nối.
            flow.kill()

addons = [Blocker()]