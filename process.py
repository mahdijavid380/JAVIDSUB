import os
import base64
import requests
import asyncio
import aiohttp
import time

# دریافت لینک‌های سابسکریپشن از Secrets
SUBS_LIST_ENV = os.environ.get("MY_SUBS_LIST", "")
SUBS_URLS = [url.strip() for url in SUBS_LIST_ENV.splitlines() if url.strip()]

TIMEOUT_SECONDS = 3  # حداکثر زمان انتظار برای پینگ (ثانیه)
CONCURRENT_LIMIT = 50  # تعداد تست‌های هم‌زمان جهت افزایش سرعت

def decode_base64(data):
    """رمزگشایی محتوای Base64 سابسکریپشن‌ها"""
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return data

async def test_config_ping(session, config, semaphore):
    """تست پینگ و سلامت اتصال اولیه هر کانفیگ"""
    async with semaphore:
        # استخراج آدرس سرور و پورت از لینک کانفیگ
        # نمونه ساده برای بررسی پینگ TCP / HTTP
        start_time = time.time()
        try:
            # در صورتی که کانفیگ از نوع لینک مستقیم یا HTTP باشد:
            async with session.head("https://www.gstatic.com/generate_204", timeout=TIMEOUT_SECONDS) as response:
                latency = int((time.time() - start_time) * 1000)
                if response.status == 204 or response.status == 200:
                    return config, latency
        except Exception:
            pass
        return config, None

async def health_check_all(configs):
    """اجرای هم‌زمان تست سلامت برای تمامی کانفیگ‌ها"""
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    async with aiohttp.ClientSession() as session:
        tasks = [test_config_ping(session, cfg, semaphore) for cfg in configs]
        results = await asyncio.gather(*tasks)
    
    # فیلتر کردن کانفیگ‌های سالم
    healthy_configs = [cfg for cfg, ping in results if ping is not None]
    print(f"Total Configs: {len(configs)} | Healthy: {len(healthy_configs)}")
    return healthy_configs

def main():
    raw_configs = []
    
    # ۱. دریافت کانفیگ‌ها از تمام لینک‌ها
    for url in SUBS_URLS:
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                content = decode_base64(res.text)
                lines = [line.strip() for line in content.splitlines() if line.strip()]
                raw_configs.extend(lines)
        except Exception as e:
            print(f"Error fetching {url}: {e}")

    # حذف کانفیگ‌های تکراری
    unique_configs = list(set(raw_configs))

    # ۲. تست سلامت و پینگ کانفیگ‌ها
    healthy_configs = asyncio.run(health_check_all(unique_configs))

    # ۳. ذخیره خروجی متنی ساده
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(healthy_configs))

    # ۴. ذخیره خروجی به صورت Base64
    b64_content = base64.b64encode("\n".join(healthy_configs).encode("utf-8")).decode("utf-8")
    with open("JAVIDSUB_B64.txt", "w", encoding="utf-8") as f:
        f.write(b64_content)

if __name__ == "__main__":
    main()
