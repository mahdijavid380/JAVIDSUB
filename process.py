import os
import json
import base64
import hashlib
import asyncio
import requests
from urllib.parse import urlparse

# ---------- تنظیمات ----------
CHUNK_SIZE = 4000  # حداکثر تعداد کانفیگ در هر فایل
VALID_PROTOCOLS = (
    "vless://", "vmess://", "trojan://",
    "ss://", "shadowsocks://", "tuic://", "hy2://",
)

# فیلتر سلامت (TCP Ping) — با متغیر محیطی قابل خاموش/روشن است
ENABLE_HEALTH_CHECK = os.getenv("ENABLE_HEALTH_CHECK", "true").lower() == "true"
HEALTH_TIMEOUT = 3              # ثانیه برای هر کانفیگ
MAX_CONCURRENT_CHECKS = 200     # حداکثر اتصال هم‌زمان
HEALTH_BATCH_SIZE = 5000        # بچ‌بندی برای محدود کردن حافظه


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
    """حذف براکت‌های IPv6 برای استفاده در سوکت."""
    if host and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


# ---------- استخراج host:port (برای اعتبارسنجی + تست سلامت) ----------
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
    """استخراج (host, port) از هر نوع کانفیگ."""
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


# ---------- (الف) فیلتر ساختاری و اعتبارسنجی ----------
def is_valid_config(line: str) -> bool:
    """اعتبارسنجی فرمت + وجود فیلدهای اجباری."""
    line = line.strip()
    if not line or not line.startswith(tuple(VALID_PROTOCOLS)):
        return False
    return extract_host_port(line) is not None


# ---------- (الف) اثر انگشت یکتا برای حذف تکراری ----------
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


# ---------- (ج) فیلتر سلامت — TCP Ping ----------
async def _tcp_check(host: str, port: int, sem: asyncio.Semaphore) -> bool:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=HEALTH_TIMEOUT,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


async def health_check_all(configs):
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async def check_one(c):
        hp = extract_host_port(c)
        if not hp:
            return False
        host, port = hp
        return await _tcp_check(host, port, sem)

    alive = []
    total = len(configs)
    for i in range(0, total, HEALTH_BATCH_SIZE):
        batch = configs[i:i + HEALTH_BATCH_SIZE]
        results = await asyncio.gather(*(check_one(c) for c in batch))
        for c, ok in zip(batch, results):
            if ok:
                alive.append(c)
        print(f"  🔍 پیشرفت: {min(i + HEALTH_BATCH_SIZE, total)}/{total} — زنده: {len(alive)}")

    dead = total - len(alive)
    print(f"✅ زنده: {len(alive)} — ❌ مرده: {dead}")

    if total > 20 and len(alive) < total * 0.05:
        print("⚠️ هشدار: بیش از ۹۵٪ کانفیگ‌ها رد شدند. "
              "احتمالاً IPهای GitHub بلاک هستند یا تست TCP برای این سرورها معتبر نیست.")
    return alive


# ---------- منطق اصلی ----------
def fetch_and_process_subs():
    raw_subs = os.getenv("MY_SUBS_LIST", "")
    if not raw_subs:
        print("❌ هیچ لینکی در MY_SUBS_LIST یافت نشد.")
        return

    sub_urls = [u.strip() for u in raw_subs.replace(",", "\n").splitlines() if u.strip()]
    print(f"📥 تعداد منابع: {len(sub_urls)}")

    # (الف) دریافت + اعتبارسنجی + حذف تکراری هوشمند
    unique_configs = {}  # fingerprint -> config

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

    final_list = sorted(unique_configs.values())
    print(f"\n📊 کانفیگ‌های یکتا و معتبر قبل از فیلتر سلامت: {len(final_list)}")

    # (ج) فیلتر سلامت
    if ENABLE_HEALTH_CHECK and final_list:
        print(f"🔍 شروع تست سلامت (timeout={HEALTH_TIMEOUT}s, "
              f"concurrency={MAX_CONCURRENT_CHECKS})...")
        final_list = asyncio.run(health_check_all(final_list))

    if not final_list:
        print("⚠️ هیچ کانفیگی برای ذخیره وجود ندارد.")
        return

    # پاک‌سازی فایل‌های قدیمی
    for f in os.listdir("."):
        if f.startswith("JAVIDSUB_") and f.endswith(".txt"):
            try:
                os.remove(f)
            except OSError:
                pass

    # تقسیم به فایل‌های ۴۰۰۰تایی + تولید نسخه Base64
    num_chunks = (len(final_list) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(num_chunks):
        chunk = final_list[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
        plain_text = "\n".join(chunk)

        txt_name = f"JAVIDSUB_{i+1:03d}.txt"
        with open(txt_name, "w", encoding="utf-8") as f:
            f.write(plain_text)

        b64_name = f"JAVIDSUB_{i+1:03d}_B64.txt"
        with open(b64_name, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(plain_text.encode("utf-8")).decode("utf-8"))

        print(f"💾 {txt_name} ({len(chunk)} کانفیگ)")

    print(f"\n🎉 عملیات انجام شد. {num_chunks} فایل ایجاد شد. "
          f"مجموع کانفیگ نهایی: {len(final_list)}")


if __name__ == "__main__":
    fetch_and_process_subs()
