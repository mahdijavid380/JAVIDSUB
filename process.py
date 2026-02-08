import requests
import base64
import os
from urllib.parse import urlparse

def get_source_name(url):
    domain = urlparse(url).netloc
    if 'github' in domain:
        return url.split('/')[-1][:10]
    return domain.split('.')[0]

def process():
    urls = []
    # ۱. لینک‌های عمومی
    try:
        with open('providers.txt', 'r') as f:
            urls.extend(f.read().splitlines())
    except: pass

    # ۲. لینک‌های شخصی از Secrets
    private_subs = os.getenv('MY_SUBS_LIST')
    if private_subs:
        urls.extend(private_subs.strip().splitlines())

    final_configs = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    for url in urls:
        url = url.strip()
        if not url or not url.startswith('http'): continue
        try:
            tag = get_source_name(url)
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                content = res.text.strip()
                try:
                    # تلاش برای دکود کردن اگر بیس۶۴ بود
                    configs = base64.b64decode(content).decode('utf-8').splitlines()
                except:
                    configs = content.splitlines()

                for config in configs:
                    config = config.strip()
                    if '://' in config:
                        # حذف نام قبلی و افزودن تگ جدید
                        base_part = config.split('#')[0]
                        final_configs.append(f"{base_part}#({tag})-JAVIDSUB")
        except Exception as e:
            print(f"Error on {url}: {e}")

    # حذف تکراری‌ها
    unique_configs = list(dict.fromkeys(final_configs))
    final_text = '\n'.join(unique_configs)

    # ۳. ذخیره فایل ساده
    with open('JAVIDSUB.txt', 'w') as f:
        f.write(final_text)

    # ۴. ذخیره فایل بیس۶۴
    with open('JAVIDSUB_B64.txt', 'w') as f:
        encoded = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
        f.write(encoded)

    print(f"Done! Processed {len(unique_configs)} configs.")

if __name__ == "__main__":
    process()
