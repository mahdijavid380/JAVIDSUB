import requests
import base64
import os
from urllib.parse import urlparse

def get_source_name(url):
    domain = urlparse(url).netloc
    if 'github' in domain:
        parts = url.split('/')
        return parts[-1] if parts[-1] else parts[-2]
    return domain.split('.')[0]

def get_psg_links():
    print("Fetching sources from PSG Repository...")
    psg_api_url = "https://api.github.com/repos/itsyebekhe/PSG/contents/subscriptions/channels"
    try:
        res = requests.get(psg_api_url, timeout=15)
        if res.status_code == 200:
            files = res.json()
            return [file['download_url'] for file in files if file['type'] == 'file']
    except:
        print("Warning: Could not fetch PSG list.")
    return []

def process():
    # ترکیب لینک‌های PSG + فایل داخلی + سکرت‌های شخصی
    urls = get_psg_links()
    
    try:
        with open('providers.txt', 'r') as f:
            urls.extend(f.read().splitlines())
    except: pass

    private_subs = os.getenv('MY_SUBS_LIST')
    if private_subs:
        urls.extend(private_subs.strip().splitlines())

    full_configs = []
    lite_configs = []
    seen_contents = set() # برای حذف تکراری‌های واقعی
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    # پروتکل‌های منتخب برای نسخه Lite
    lite_protocols = ['vless://', 'vmess://', 'trojan://']

    for url in urls:
        url = url.strip()
        if not url or not url.startswith('http'): continue
        try:
            tag = get_source_name(url)
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                content = res.text.strip()
                try:
                    configs = base64.b64decode(content).decode('utf-8').splitlines()
                except:
                    configs = content.splitlines()

                for config in configs:
                    config = config.strip()
                    if '://' in config:
                        # جداسازی بخش اصلی برای تشخیص تکراری
                        config_core = config.split('#')[0]
                        if config_core not in seen_contents:
                            seen_contents.add(config_core)
                            new_config = f"{config_core}#({tag})-JAVIDSUB"
                            
                            full_configs.append(new_config)
                            
                            if any(config.startswith(p) for p in lite_protocols):
                                lite_configs.append(new_config)
        except: continue

    # ۱. ذخیره فایل کامل (Text)
    with open('JAVIDSUB.txt', 'w') as f:
        f.write('\n'.join(full_configs))

    # ۲. ذخیره فایل کامل (Base64)
    with open('JAVIDSUB_B64.txt', 'w') as f:
        encoded = base64.b64encode('\n'.join(full_configs).encode('utf-8')).decode('utf-8')
        f.write(encoded)

    # ۳. ذخیره فایل سبک (Lite)
    with open('LITE_SUB.txt', 'w') as f:
        f.write('\n'.join(lite_configs))

    print(f"Update Successful! Full: {len(full_configs)} | Lite: {len(lite_configs)}")

if __name__ == "__main__":
    process()
