from sms import SendSms
import threading

def is_enough(phone, email, count, mode):
    sms = SendSms(phone, email)
    servisler_sms = []

    for attr in dir(SendSms):
        if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
            servisler_sms.append(attr)

    lock = threading.Lock()  # Thread-safe counter
    sent_count = 0
    failed_count = 0
    total_attempts = 0

    def run_service(func):
        nonlocal sent_count, failed_count, total_attempts
        with lock:
            if total_attempts >= count:
                return
            total_attempts += 1
        try:
            getattr(sms, func)()
            with lock:
                sent_count += 1
        except Exception:
            with lock:
                failed_count += 1

    if mode == "turbo":
        threads_per_cycle = min(10, len(servisler_sms))  # Maks 10 thread, Render’a uygun
        while total_attempts < count:
            threads = []
            for _ in range(min(threads_per_cycle, count - total_attempts)):
                for func in servisler_sms[:threads_per_cycle]:  # Sınırlı servis
                    if total_attempts >= count:
                        break
                    t = threading.Thread(target=run_service, args=(func,))
                    threads.append(t)
                    t.start()
            for t in threads:
                t.join()
    else:
        while total_attempts < count:
            for func in servisler_sms:
                if total_attempts >= count:
                    break
                run_service(func)

    print(f"[+] Başarılı! {sent_count} SMS gönderildi")
    for _ in range(failed_count):
        print("[-] Başarısız!")
    return sent_count, failed_count
