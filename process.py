import os
import json
import base64
import hashlib
import asyncio
import random
import requests
from pathlib import Path
from urllib.parse import urlparse

try:
    from python_v2ray.downloader import BinaryDownloader
    from python_v2ray.tester import ConnectionTester
    from python_v2ray.config_parser import parse_uri
    HAS_V2RAY_LIB = True
except ImportError:
    HAS_V2RAY_LIB = False
    print("⚠️ کتابخانه python-v2ray نصب نیست. به تست TCP سوئیچ می‌شود.")

# ---------- تنظیمات ----------
MAX_OUTPUT = int(os.getenv("MAX_OUTPUT", "2000"))
MAX_TEST_LIMIT = 5000 # حداکثر کانفیگی که تست واقعی می‌شود تا سرور کرش نکند
VALID_PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "shadowsocks://", "tuic://", "hy2://")

# ---------- توابع کمکی پایه ----------
def decode_base64_if_needed(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith(tuple(VALID_PROTOCOLS)):
        return stripped
    try:
        return _decode_b64_safe(stripped)
    except Exception:
        return text

def _decode_b64_safe(s: str) -> str:
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.b64decode(s).decode("utf-8", errors="ignore")

def _clean_host(host: str) -> str:
    if host and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host

def extract_ss_host_port(config: str):
    try:
        body = config.split("://", 1)[1]
        if "#" in body: body = body.split("#", 1)[0]
        if "@" in body:
            _, hostport = body.rsplit("@", 1)
            hostport = hostport.split("/")[0].split("?")[0]
            host, port = hostport.rsplit(":", 1)
            return _clean_host(host), int(port)
        else:
            decoded = _decode_b64_safe(body)
            if "@" in decoded:
                _, hostport = decoded.rsplit("@", 1)
                hostport = hostport.split("/")[0].split("?")[0]
                host, port = hostport.rsplit(":", 1)
                return _clean_host(host), int(port)
    except Exception:
        pass
    return None

def extract_host_port(config: str):
    try:
        if config.startswith("vmess://"):
            data = json.loads(_decode_b64_safe(config[8:].strip()))
            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 0))
            if not host or not port or not data.get("id"): return None
            return _clean_host(host), port
        if config.startswith("ss://") or config.startswith("shadowsocks://"):
            return extract_ss_host_port(config)
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port
        if host and port: return _clean_host(host), port
    except Exception:
        pass
    return None

def is_valid_config(line: str) -> bool:
    line = line.strip()
    return line and line.startswith(tuple(VALID_PROTOCOLS)) and extract_host_port(line) is not None

def extract_fingerprint(config: str) -> str:
    hp = extract_host_port(config)
    if not hp: return hashlib.md5(config.encode()).hexdigest()
    host, port = hp
    scheme = config.split("://", 1)[0]
    try:
        if config.startswith("vmess://"):
            data = json.loads(_decode_b64_safe(config[8:].strip()))
            auth = data.get("id", "")
            transport = "|".join(str(data.get(k, "")) for k in ("net", "type", "path", "host", "tls"))
        else:
            parsed = urlparse(config)
            auth = parsed.username or parsed.password or ""
            transport = parsed.query
        key = f"{scheme}|{host}|{port}|{auth}|{transport}"
    except Exception:
        key = config
    return hashlib.md5(key.encode()).hexdigest()

# ---------- تست واقعی (با محافظت از کرش) ----------
def real_health_check(configs):
    if not HAS_V2RAY_LIB:
        return []

    project_root = Path("./")
    print("⏳ آماده‌سازی هسته Xray...")
    try:
        downloader = BinaryDownloader(project_root)
        downloader.ensure_all()
    except Exception as e:
        print(f"❌ خطا در دانلود هسته: {e}")
        return []

    parsed_configs = []
    for uri in configs:
        try:
            p = parse_uri(uri)
            if p: parsed_configs.append(p)
        except Exception:
            pass

    if not parsed_configs:
        print("⚠️ هیچ کانفیگ قابل‌تستی یافت نشد.")
        return []

    # جلوگیری از کرش با محدود کردن تعداد تست
    if len(parsed_configs) > MAX_TEST_LIMIT:
        random.shuffle(parsed_configs)
        parsed_configs = parsed_configs[:MAX_TEST_LIMIT]
        print(f"⚠️ برای جلوگیری از تایم‌اوت، فقط {MAX_TEST_LIMIT} کانفیگ به صورت تصادفی تست می‌شوند.")

    print(f"🚀 شروع تست واقعی برای {len(parsed_configs)} کانفیگ...")
    try:
        tester = ConnectionTester(
            vendor_path=str(project_root / "vendor"),
            core_engine_path=str(project_root / "core_engine")
        )
        results = tester.test_uris(parsed_configs)
    except Exception as e:
        print(f"❌ خطای مهلک در هسته Xray: {e}")
        return []

    working = []
    for r in results:
        if r.get('status') == 'success':
            working.append({'uri': r.get('uri'), 'ping': r.get('ping_ms', 9999)})
            
    working.sort(key=lambda x: x['ping'])
    print(f"✅ کانفیگ‌های واقعاً سالم: {len(working)}")
    return [w['uri'] for w in working]

# ---------- تست TCP (سیستم پشتیبان) ----------
async def tcp_check(host, port):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        writer.close()
        return True
    except Exception:
        return False

def backup_tcp_test(configs):
    print("⚠️ استفاده از تست TCP به عنوان سیستم پشتیبان...")
    async def check_all():
        tasks = []
        for c in configs:
            hp = extract_host_port(c)
            if hp: tasks.append((c, tcp_check(hp[0], hp[1])))
        results = await asyncio.gather(*(t[1] for t in tasks))
        return [t[0] for t, ok in zip(tasks, results) if ok]
    
    return asyncio.run(check_all())

# ---------- منطق اصلی ----------
def fetch_and_process_subs():
    raw_subs = os.getenv("MY_SUBS_LIST", "")
    if not raw_subs:
        print("❌ لینک‌ها یافت نشد.")
        return

    sub_urls = [u.strip() for u in raw_subs.replace(",", "\n").splitlines() if u.strip()]
    unique_configs = {}

    for url in sub_urls:
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            decoded = decode_base64_if_needed(resp.text.strip())
            for line in decoded.splitlines():
                line = line.strip()
                if is_valid_config(line):
                    fp = extract_fingerprint(line)
                    if fp not in unique_configs:
                        unique_configs[fp] = line
        except Exception as e:
            print(f"❌ خطا در دریافت {url}: {e}")

    final_list = list(unique_configs.values())
    print(f"\n📊 کل کانفیگ‌های یکتا: {len(final_list)}")

    if final_list:
        # تلاش برای تست واقعی
        tested_list = real_health_check(final_list)
        
        # اگر تست واقعی خروجی داد، از آن استفاده کن. در غیر این صورت، برو سراغ تست TCP
        if tested_list:
            final_list = tested_list
        else:
            print("⚠️ تست Xray خروجی نداد. سوئیچ به تست TCP...")
            final_list = backup_tcp_test(final_list)

    if not final_list:
        print("⚠️ هیچ کانفیگ سالمی پیدا نشد. فایلی ساخته نمی‌شود.")
        return

    if len(final_list) > MAX_OUTPUT:
        final_list = final_list[:MAX_OUTPUT]

    # پاک‌سازی
    for f in os.listdir("."):
        if f.startswith("JAVIDSUB") and f.endswith(".txt"):
            try: os.remove(f)
            except: pass

    # ذخیره
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))

    print(f"\n🎉 فایل JAVIDSUB.txt با {len(final_list)} کانفیگ ذخیره شد.")

if __name__ == "__main__":
    fetch_and_process_subs()
