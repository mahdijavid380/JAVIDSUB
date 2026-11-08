import os
import json
import base64
import hashlib
import requests
from pathlib import Path
from urllib.parse import urlparse

# ---------- کتابخانه تست واقعی ----------
from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from python_v2ray.config_parser import parse_uri

# ---------- تنظیمات ----------
MAX_OUTPUT = int(os.getenv("MAX_OUTPUT", "2000")) # حداکثر کانفیگ خروجی
VALID_PROTOCOLS = (
    "vless://", "vmess://", "trojan://",
    "ss://", "shadowsocks://", "tuic://", "hy2://",
)

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

# ---------- استخراج host:port ----------
def extract_ss_host_port(config: str):
    try:
        body = config.split("://", 1)[1]
        if "#" in body:
            body = body.split("#", 1)[0]
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
            if not host or not port or not data.get("id"):
                return None
            return _clean_host(host), port

        if config.startswith("ss://") or config.startswith("shadowsocks://"):
            return extract_ss_host_port(config)

        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return _clean_host(host), port
    except Exception:
        pass
    return None

# ---------- اعتبارسنجی ساختاری ----------
def is_valid_config(line: str) -> bool:
    line = line.strip()
    if not line or not line.startswith(tuple(VALID_PROTOCOLS)):
        return False
    return extract_host_port(line) is not None

# ---------- اثر انگشت یکتا ----------
def extract_fingerprint(config: str) -> str:
    hp = extract_host_port(config)
    if not hp:
        return hashlib.md5(config.encode()).hexdigest()

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

# ---------- تست واقعی با هسته Xray ----------
def real_health_check(configs):
    project_root = Path("./")
    print("⏳ آماده‌سازی هسته Xray (دانلود خودکار)...")
    try:
        downloader = BinaryDownloader(project_root)
        downloader.ensure_all()
    except Exception as e:
        print(f"❌ خطا در آماده‌سازی هسته: {e}")
        return []

    parsed_configs = [p for p in (parse_uri(uri) for uri in configs) if p]
    if not parsed_configs:
        print("⚠️ هیچ کانفیگ قابل‌تستی یافت نشد.")
        return []

    print(f"🚀 شروع تست واقعی برای {len(parsed_configs)} کانفیگ... (ممکن است چند دقیقه طول بکشد)")
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine")
    )
    
    # اجرای تست
    results = tester.test_uris(parsed_configs)

    working = []
    for r in results:
        if r.get('status') == 'success':
            working.append({
                'uri': r.get('uri'),
                'ping': r.get('ping_ms', 9999)
            })
            
    # مرتب‌سازی بر اساس کمترین پینگ (سریع‌ترین‌ها)
    working.sort(key=lambda x: x['ping'])
    print(f"✅ کانفیگ‌های واقعاً سالم: {len(working)}")
    return [w['uri'] for w in working]

# ---------- منطق اصلی ----------
def fetch_and_process_subs():
    raw_subs = os.getenv("MY_SUBS_LIST", "")
    if not raw_subs:
        print("❌ هیچ لینکی در MY_SUBS_LIST یافت نشد.")
        return

    sub_urls = [u.strip() for u in raw_subs.replace(",", "\n").splitlines() if u.strip()]
    print(f"📥 تعداد منابع: {len(sub_urls)}")

    unique_configs = {}

    for url in sub_urls:
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            content = resp.text.strip()
            if not content:
                print(f"⚠️ پاسخ خالی از {url}")
                continue

            decoded = decode_base64_if_needed(content)
            added = 0
            for line in decoded.splitlines():
                line = line.strip()
                if not is_valid_config(line):
                    continue
                fp = extract_fingerprint(line)
                if fp not in unique_configs:
                    unique_configs[fp] = line
                    added += 1

            print(f"✅ {url} — {added} کانفیگ جدید (کل: {len(unique_configs)})")
        except Exception as e:
            print(f"❌ خطا در {url}: {e}")

    final_list = list(unique_configs.values())
    print(f"\n📊 کانفیگ‌های یکتا و معتبر قبل از تست: {len(final_list)}")

    # تست واقعی
    if final_list:
        final_list = real_health_check(final_list)

    if not final_list:
        print("⚠️ هیچ کانفیگ سالمی برای ذخیره وجود ندارد.")
        return

    # محدود کردن به ۲۰۰۰ کانفیگ برتر
    if len(final_list) > MAX_OUTPUT:
        print(f"✂️ انتخاب {MAX_OUTPUT} کانفیگ برتر از {len(final_list)} کانفیگ سالم...")
        final_list = final_list[:MAX_OUTPUT]

    # پاک‌سازی فایل‌های قدیمی
    for f in os.listdir("."):
        if f.startswith("JAVIDSUB") and f.endswith(".txt"):
            try:
                os.remove(f)
            except OSError:
                pass

    # ذخیره در یک فایل واحد
    plain_text = "\n".join(final_list)
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    print(f"\n🎉 عملیات انجام شد.")
    print(f"📄 فایل خروجی: JAVIDSUB.txt")
    print(f"🔢 تعداد کانفیگ نهایی: {len(final_list)}")

if __name__ == "__main__":
    fetch_and_process_subs()
