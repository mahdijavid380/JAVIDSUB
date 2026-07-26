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
MAX_TIMEOUT = 4        # حداکثر زمان انتظار پینگ (ثانیه)
CONCURRENT_LIMIT = 40  # تعداد تست هم‌زمان بهینه برای Runner لینوکس گیت‌هاب
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
# پارسر جامع‌تر برای تبدیل URI به Sing-box Outbound
# ==========================================
def parse_uri_to_singbox_outbound(uri):
    try:
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        
        if scheme == "vless":
            query = parse_qs(parsed.query)
            security = query.get("security", [""])[0]
            return {
                "type": "vless",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": parsed.port or 443,
                "uuid": parsed.username,
                "flow": query.get("flow", [""])[0],
                "tls": {
                    "enabled": security in ["tls", "reality"],
                    "server_name": query.get("sni", [""])[0] or query.get("host", [""])[0],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": security == "reality",
                        "public_key": query.get("pbk", [""])[0],
                        "short_id": query.get("sid", [""])[0]
                    } if security == "reality" else None
                } if security in ["tls", "reality"] else None,
                "transport": {
                    "type": query.get("type", ["tcp"])[0],
                    "path": query.get("path", [""])[0],
                    "headers": {"Host": query.get("host", [""])[0]} if query.get("host") else None
                } if query.get("type", ["tcp"])[0] != "tcp" else None
            }

        elif scheme == "vmess":
            # پارس کانفیگ‌های VMess که به صورت Base64 encoded JSON هستند
            vmess_raw = decode_base64(parsed.netloc if not parsed.hostname else parsed.path)
            v_data = json.loads(vmess_raw)
            return {
                "type": "vmess",
                "tag": "proxy",
                "server": v_data.get("add"),
                "server_port": int(v_data.get("port", 443)),
                "uuid": v_data.get("id"),
                "security": v_data.get("scy", "auto"),
                "alter_id": int(v_data.get("aid", 0)),
                "tls": {
                    "enabled": v_data.get("tls") == "tls",
                    "server_name": v_data.get("sni") or v_data.get("host")
                } if v_data.get("tls") == "tls" else None
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

def clean_dict(d):
    """حذف کلیدهای None جهت جلوگیری از خطای JSON در Sing-box"""
    if not isinstance(d, dict):
        return d
    return {k: clean_dict(v) for k, v in d.items() if v is not None}

def create_singbox_config(outbound, socks_port):
    return {
        "log": {"level": "panic"},
        "dns": {
            "servers": [{"tag": "dns-remote", "address": "udp://1.1.1.1"}]
        },
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

# ==========================================
# تست هم‌زمان بدون نوشتن روی دیسک (In-Memory STDIN)
# ==========================================
async def test_single_config(semaphore, config_str, worker_id, results):
    socks_port = BASE_PORT + worker_id
    outbound = parse_uri_to_singbox_outbound(config_str)
    
    if not outbound or not outbound.get("server"):
        return

    async with semaphore:
        config_json = create_singbox_config(outbound, socks_port)
        config_bytes = json.dumps(config_json).encode('utf-8')

        sb_process = None
        try:
            # ۱. ارسال مستقیم کانفیگ به STDIN پردازش Sing-box (حذف I/O دیسک)
            sb_process = await asyncio.create_subprocess_exec(
                "./sing-box", "run", "-c", "-",
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # ارسال بایتهای JSON به پروسه
            sb_process.stdin.write(config_bytes)
            await sb_process.stdin.drain()
            sb_process.stdin.close()

            await asyncio.sleep(0.15) # کاهش زمان انتظار برای بالا آمدن اینباند

            # ۲. سنجش تاخیر با cURL
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
                print(f"[OK] {outbound['type'].upper()} | {latency}ms")
                results.append((config_str, latency))
            else:
                print(f"[FAIL] {outbound['type'].upper()}")

        except Exception:
            pass
        finally:
            # ۳. پاک‌سازی قطعی پروسه از حافظه RAM
            if sb_process:
                try:
                    sb_process.kill()
                    await sb_process.wait()
                except Exception:
                    pass

async def main_async(unique_configs):
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    results = []
    tasks = []

    for idx, cfg in enumerate(unique_configs):
        worker_id = idx % CONCURRENT_LIMIT
        tasks.append(test_single_config(semaphore, cfg, worker_id, results))

    await asyncio.gather(*tasks)

    # مرتب‌سازی کانفیگ‌های سالم بر اساس پینگ
    results.sort(key=lambda x: x[1])
    return [item[0] for item in results]

def main():
    print("Fetching subscriptions...")
    raw_configs = []
    
    for url in SUBS_URLS:
        try:
            res = requests.get(url, timeout=8)
            if res.status_code == 200:
                content = decode_base64(res.text)
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                raw_configs.extend(lines)
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    unique_configs = list(set(raw_configs))
    print(f"Total Unique Configs: {len(unique_configs)}")
    print(f"Starting Optimized Real-Delay Test (Concurrency: {CONCURRENT_LIMIT})...\n")

    healthy_configs = asyncio.run(main_async(unique_configs))

    print(f"\nFinished! Healthy Configs: {len(healthy_configs)} / {len(unique_configs)}")

    # ۱. خروجی متنی
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(healthy_configs))

    # ۲. خروجی Base64
    b64_content = base64.b64encode("\n".join(healthy_configs).encode("utf-8")).decode("utf-8")
    with open("JAVIDSUB_B64.txt", "w", encoding="utf-8") as f:
        f.write(b64_content)

if __name__ == "__main__":
    main()
