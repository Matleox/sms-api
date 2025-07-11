from sms import SendSms
import threading

def is_enough(phone, email, count, mode):
    sms = SendSms(phone, email)
    servisler_sms = []

    for attr in dir(SendSms):
        if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
            servisler_sms.append(attr)

    sent_count = 0
    failed_count = 0

    def run_service(func):
        nonlocal sent_count, failed_count
        try:
            getattr(sms, func)()
            sent_count += 1
        except Exception:
            failed_count += 1  # Hata verirse başarısız say

    if mode == "turbo":
        for _ in range(count):
            threads = []
            for func in servisler_sms:
                t = threading.Thread(target=run_service, args=(func,))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
    else:
        for _ in range(count):
            for func in servisler_sms:
                run_service(func)

    print(f"[+] Başarılı! {sent_count} SMS gönderildi")
    for _ in range(failed_count):
        print("[-] Başarısız!")
    return sent_count, failed_count  # Başarı ve başarısızlık sayısını döndür
