from sms import SendSms
import threading

def is_enough(phone, email, count, mode):
    sms = SendSms(phone, email)
    servisler_sms = []

    for attr in dir(SendSms):
        if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
            servisler_sms.append(attr)

    lock = threading.Lock()
    sent_count = 0
    failed_count = 0
    total_attempts = 0
    servis_index = 0

    def run_service():
        nonlocal sent_count, failed_count, total_attempts, servis_index
        with lock:
            if total_attempts >= count:
                return
            total_attempts += 1
            func = servisler_sms[servis_index]
            servis_index = (servis_index + 1) % len(servisler_sms)  # Başa sar
        try:
            getattr(sms, func)()
            with lock:
                sent_count += 1
        except Exception:
            with lock:
                failed_count += 1

    if mode == "turbo":
        for _ in range(count):
            threads = []
            t = threading.Thread(target=run_service)
            threads.append(t)
            t.start()
            for t in threads:
                t.join()
    else:
        for _ in range(count):
            run_service()

    print(f"[+] Başarılı! {sent_count} SMS gönderildi")
    for _ in range(failed_count):
        print("[-] Başarısız!")
    return sent_count, failed_count
