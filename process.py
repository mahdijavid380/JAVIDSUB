import os
import base64
import requests

def decode_base64_if_needed(text):
    """اگر محتوا بیس۶۴ باشد آن را دکود می‌کند، در غیر این صورت خود متن را برمی‌گرداند."""
    text_trimmed = text.strip()
    # بررسی ظاهری برای تشخیص بیس۶۴
    if not any(text_trimmed.startswith(proto) for proto in ["vless://", "vmess://", "trojan://", "ss://", "shadowsocks://"]):
        try:
            # اضافه کردن پدینگ در صورت نیاز
            missing_padding = len(text_trimmed) % 4
            if missing_padding:
                text_trimmed += '=' * (4 - missing_padding)
            decoded_bytes = base64.b64decode(text_trimmed)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return text
    return text

def fetch_and_process_subs():
    # دریافت لیست لینک‌ها از متغير محیطی گیت‌هاب
    raw_subs = os.getenv("MY_SUBS_LIST", "")
    if not raw_subs:
        print("هشدار: هیچ لینکی در MY_SUBS_LIST یافت نشد.")
        return

    # جداسازی آدرس‌ها (پشتیبانی از خط جدید یا فاصله‌/کاما)
    sub_urls = [url.strip() for url in raw_subs.replace(',', '\n').splitlines() if url.strip()]
    
    unique_configs = set()

    for url in sub_urls:
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                content = response.text.strip()
                decoded_content = decode_base64_if_needed(content)
                
                # استخراج تک‌تک خطوط (کانفیگ‌ها)
                lines = decoded_content.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "shadowsocks://", "tuic://", "hy2://"]):
                        unique_configs.add(line)
                print(f"موفق: دریافت اطلاعات از {url}")
            else:
                print(f"خطا در دریافت {url} - کد وضعیت: {response.status_code}")
        except Exception as e:
            print(f"خطا در اتصال به {url}: {e}")

    # تبدیل به لیست و مرتب‌سازی جهت پایداری فایل
    final_list = sorted(list(unique_configs))
    plain_text_output = "\n".join(final_list)

    # ۱. ذخیره فایل متن ساده
    with open("JAVIDSUB.txt", "w", encoding="utf-8") as f:
        f.write(plain_text_output)

    # ۲. ذخیره فایل Base64
    b64_encoded_output = base64.b64encode(plain_text_output.encode("utf-8")).decode("utf-8")
    with open("JAVIDSUB_B64.txt", "w", encoding="utf-8") as f:
        f.write(b64_encoded_output)

    print(f"عملیات با موفقیت انجام شد. تعداد کل کانفیگ‌های یکتا: {len(final_list)}")

if __name__ == "__main__":
    fetch_and_process_subs()
