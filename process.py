import os
import json
import base64
import time
import asyncio
import subprocess
import requests
from urllib.parse import urlparse, parse_qs, unquote

SUBS_LIST_ENV = os.environ.get("MY_SUBS_LIST", "")
SUBS_URLS = [url.strip() for url in SUBS_LIST_ENV.splitlines() if url.strip()]

TEST_URL = "https://www.gstatic.com/generate_204"
MAX_TIMEOUT = 5        # حداکثر زمان انتظار برای پینگ هر کانفیگ (ثانیه)
CONCURRENT_LIMIT = 50  # تعداد تست‌های هم‌زمان
BASE_PORT = 10000      # پورت شروع برای SOCKS5های محلی

def decode_base64(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return data

# ==========================================
# تبدیل لینک‌های URI به Outbound برای Sing-box
# ==========================================
def parse_uri_to_singbox_outbound(uri):
    try:
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        
        if scheme == "vless":
            query = parse_qs(parsed.query)
            return {
                "type": "vless",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "uuid": parsed.username,
                "flow": query.get("flow", [""])[0],
                "tls": {
                    "enabled": query.get("security", [""])[0] in ["tls", "reality"],
                    "server_name": query.get("sni", [""])[0] or query.get("host", [""])[0],
                    "reality": {
                        "enabled": query.get("security", [""])[0] == "reality",
                        "public_key": query.get("pbk", [""])[0],
                        "short_id": query.get("sid", [""])[0]
                    } if query.get("security", [""])[0] == "reality" else None
                } if query.get("security", [""])[0] in ["tls", "reality"] else None,
                "transport": {
                    "type": query.get("type", ["tcp"])[0],
                    "path": query.get("path", [""])[0],
                    "headers": {"Host": query.get("host", [""])[0]} if query.get("host") else None
                } if query.get("type", ["tcp"])[0] != "tcp" else None
            }

        elif scheme == "trojan":
            query = parse_qs(parsed.query)
            return {
                "type": "trojan",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "password": parsed.username,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or query.get("host", [""])[0]
                }
            }

        elif scheme == "ss":
            # Shadowsocks ساده
            user_info = decode_base64(parsed.username) if parsed.username else ""
            if ":" in user_info:
                method, password = user_info.split(":", 1)
            else:
                method, password = "aes-128-gcm", ""
            return {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port,
                "method": method,
                "password": password
            }
    except Exception:
        pass
    return None

def create_singbox_config(outbound, socks_port):
    """ساخت فایل کانفیگ JSON موقت برای Sing-box"""
    # پاک‌سازی فیلدهای None
    def clean_dict(d):
        if not isinstance(d, dict):
            return d
        return {k: clean_dict(v) for k, v in d.items() if v is not None}

    config = {
        "log": {"level": "panic"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port
            }
        ],
        "outbounds": [
            clean_dict(outbound),
            {"type": "direct", "tag": "direct"}
        ]
    }
    return config

# ==========================================
# تست Real Delay هم‌زمان با Sing-box
# ==========================================
async def test_single_config(semaphore, config_str, worker_id, results):
    socks_port = BASE_PORT + worker_id
    outbound = parse_uri_to_singbox_outbound(config_str)
    
    if not outbound:
        return

    async with semaphore:
        config_json = create_singbox_config(outbound, socks_port)
        config_file_path = f"/tmp/sb_{socks_port}.json"
        
        with open(config_file_path, "w") as f:
            json.dump(config_json, f)

        sb_process = None
        try:
            # ۱. اجرای هسته Sing-box در پس‌زمینه
            sb_process = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", config_file_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await asyncio.sleep(0.3) # زمان کوتاه جهت بالا آمدن اینباند Socks5

            # ۲. ارسال درخواست واقعی با cURL جهت سنجش Real Delay
            start_time = time.time()
            curl_process = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--socks5-hostname", f"127.0.0.1:{socks_port}",
                TEST_URL, "--max-time", str(MAX_TIMEOUT),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            stdout, _ = await curl_process.communicate()
            latency = int((time.time() - start_time) * 1000)

            http_code = stdout.decode().strip()
            if http_code in ["204", "200"] and latency < (MAX_TIMEOUT * 1000):
                print(f"[OK] {outbound['type'].upper()} | Delay: {latency}ms")
                results.append((config_str, latency))
            else:
                print(f"[FAIL] {outbound['type'].upper()} | Code: {http_code}")

        except Exception as e:
            pass
        finally:
            # ۳. بستن فرآیند Sing-box و حذف فایل temp
            if sb_process:
                try:
                    sb_process.kill()
                    await sb_process.wait()
                except Exception:
                    pass
            if os.path.exists(config_file_path):
                os.remove(config_file_path)

async def main_async(unique_configs):
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    results = []
    tasks = []

    for idx, cfg in enumerate(unique_configs):
        worker_id = idx % CONCURRENT_LIMIT
        tasks.append(test_single_config(semaphore, cfg, worker_id, results))

    await asyncio.gather(*tasks)

    # مرتب‌سازی کانفیگ‌ها بر اساس پایین‌ترین پینگ
    results.sort(key=lambda x: x[1])
    sorted_configs = [item[0] for item in results]
    return sorted_configs

def main():
    print("Fetching subscription links...")
    raw_configs = []
    
    for url in SUBS_URLS:
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                content = decode_base64(res.text)
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                raw_configs.extend(lines)
        except Exception as e:
            print(f"Error reading {url}: {e}")

    unique_configs = list(set(raw_configs))
    print(f"Total Unique Configs: {len(unique_configs)}")
    print(f"Starting Real Delay test (Concurrency: {CONCURRENT_LIMIT})...\n")

    # اجرای تست‌های هم‌زمان
    healthy_configs = asyncio.run(main_async(unique_configs))

    print(f"\nTest Finished. Healthy Configs: {len(healthy_configs)} / {len(unique_configs)}")

    # ۱. ذخیره خروجی متنی (JAVIDSUB.txt)
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(healthy_configs))

    # ۲. ذخیره خروجی Base64 (JAVIDSUB_B64.txt)
    b64_content = base64.b64encode("\n".join(healthy_configs).encode("utf-8")).decode("utf-8")
    with open("JAVIDSUB_B64.txt", "w", encoding="utf-8") as f:
        f.write(b64_content)

if __name__ == "__main__":
    main()
