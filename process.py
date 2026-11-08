import os
import json
import base64
import hashlib
import asyncio
import time
import requests
from urllib.parse import urlparse

# ---------- تنظیمات ----------
MAX_OUTPUT           = int(os.getenv("MAX_OUTPUT", "2000"))   # حداکثر کانفیگ خروجی
VALID_PROTOCOLS = (
    "vless://", "vmess://", "trojan://",
    "ss://", "shadowsocks://", "tuic://", "hy2://",
)

ENABLE_HEALTH_CHECK  = os.getenv("ENABLE_HEALTH_CHECK", "true").lower() == "true"
HEALTH_TIMEOUT       = float(os.getenv("HEALTH_TIMEOUT", "5"))    # ثانیه
MAX_CONCURRENT_CHECKS= int(os.getenv("MAX_CONCURRENT_CHECKS", "200"))
HEALTH_BATCH_SIZE    = int(os.getenv("HEALTH_BATCH_SIZE", "2000"))
CHECK_ROUNDS         = int(os.getenv("CHECK_ROUNDS", "3"))        # تعداد راند تست پایداری
ROUND_DELAY          = 0.2                                        # تاخیر بین راندها


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


# ---------- تست سلامت قوی: TCP Ping + Latency + پایداری ----------
async def _tcp_check_latency(host: str, port: int, sem: asyncio.Semaphore):
    """تلاش برای اتصال TCP و برگرداندن تاخیر (ms) یا None در صورت شکست."""
    async with sem:
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=HEALTH_TIMEOUT,
            )
            latency = (time.monotonic() - start) * 1000.0
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return latency
        except Exception:
            return None


async def health_check_all(configs):
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async def check_one(c):
        hp = extract_host_port(c)
        if not hp:
            return c, None, 0
        host, port = hp
        latencies = []
        for r in range(CHECK_ROUNDS):
            lat = await _tcp_check_latency(host, port, sem)
            if lat is not None:
                latencies.append(lat)
            elif r == 0:
                # راند اول شکست خورد → احتمالاً مرده است، صرفه‌جویی در زمان
                return c, None, 0
            if r < CHECK_ROUNDS - 1:
                await asyncio.sleep(ROUND_DELAY)
        if not latencies:
            return c, None, 0
        return c, sum(latencies) / len(latencies), len(latencies)

    scored = []
    total = len(configs)
    for i in range(0, total, HEALTH_BATCH_SIZE):
        batch = configs[i:i + HEALTH_BATCH_SIZE]
        batch_results = await asyncio.gather(*(check_one(c) for c in batch))
        for c, avg, s in batch_results:
            if s > 0:
                scored.append((c, avg, s))
        print(f"  🔍 پیشرفت: {min(i + HEALTH_BATCH_SIZE, total)}/{total} — زنده: {len(scored)}")

    # رتبه‌بندی: اول پایداری بیشتر، بعد تاخیر کمتر
    scored.sort(key=lambda x: (-x[2], x[1]))

    if scored:
        best = scored[0]
        worst = scored[-1]
        print(f"⚡ سریع‌ترین: {best[1]:.0f}ms ({best[2]}/{CHECK_ROUNDS} راند)")
        print(f"🐢 کندترینِ قبول‌شده: {worst[1]:.0f}ms ({worst[2]}/{CHECK_ROUNDS} راند)")

    print(f"✅ زنده و باکیفیت: {len(scored)} از {total}")
    return [c for c, _, _ in scored]


# ---------- منطق اصلی ----------
def fetch_and_process_subs():
    raw_subs = os.getenv("MY_SUBS_LIST", "")
    if not raw_subs:
        print("❌ هیچ لینکی در MY_SUBS_LIST یافت نشد.")
        return

    sub_urls = [u.strip() for u in raw_subs.replace(",", "\n").splitlines() if u.strip()]
    print(f"📥 تعداد منابع: {len(sub_urls)}")

    # دریافت + اعتبارسنجی + حذف تکراری هوشمند
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
    print(f"\n📊 کانفیگ‌های یکتا و معتبر قبل از فیلتر سلامت: {len(final_list)}")

    # تست سلامت قوی
    if ENABLE_HEALTH_CHECK and final_list:
        print(f"🔍 شروع تست سلامت قوی ({CHECK_ROUNDS} راند، timeout={HEALTH_TIMEOUT}s، "
              f"concurrency={MAX_CONCURRENT_CHECKS})...")
        final_list = asyncio.run(health_check_all(final_list))
    else:
        # بدون تست، ترتیب الفبایی حفظ می‌شود
        final_list = sorted(final_list)

    if not final_list:
        print("⚠️ هیچ کانفیگی برای ذخیره وجود ندارد.")
        return

    # محدود کردن به MAX_OUTPUT (۲۰۰۰)
    if len(final_list) > MAX_OUTPUT:
        print(f"✂️ انتخاب {MAX_OUTPUT} کانفیگ برتر از {len(final_list)} کانفیگ زنده...")
        final_list = final_list[:MAX_OUTPUT]

    # پاک‌سازی فایل‌های قدیمی (هم چانک‌دار قدیمی هم تک‌فایل)
    for f in os.listdir("."):
        if f.startswith("JAVIDSUB") and f.endswith(".txt"):
            try:
                os.remove(f)
            except OSError:
                pass

    # فقط یک فایل خروجی
    plain_text = "\n".join(final_list)
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    print(f"\n🎉 عملیات انجام شد.")
    print(f"📄 فایل خروجی: JAVIDSUB.txt")
    print(f"🔢 تعداد کانفیگ نهایی: {len(final_list)}")


if __name__ == "__main__":
    fetch_and_process_subs()
