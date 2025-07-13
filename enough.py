sent_count = 0
failed_count = 0
total_attempts = 0
servis_index = 0

    def run_service(thread_id):
        nonlocal sent_count, failed_count, total_attempts
        local_index = thread_id % len(servisler_sms)  # Her thread farklı başlasın
        while True:
    def run_service():
        nonlocal sent_count, failed_count, total_attempts, servis_index
        with lock:
            if total_attempts >= count:
                return
            total_attempts += 1
            func = servisler_sms[servis_index]
            servis_index = (servis_index + 1) % len(servisler_sms)
        try:
            getattr(sms, func)()
with lock:
                if total_attempts >= count:
                    return
                func = servisler_sms[local_index]
                local_index = (local_index + 1) % len(servisler_sms)  # Baştan sar
                total_attempts += 1
            try:
                getattr(sms, func)()
                with lock:
                    sent_count += 1
            except Exception:
                with lock:
                    failed_count += 1
                sent_count += 1
        except Exception:
            with lock:
                failed_count += 1

    batch_size = min(100, count)  # Render için 100’lük batch
if mode == "turbo":
        threads = []
        for i in range(len(servisler_sms)):  # Tüm servisler kadar thread
            t = threading.Thread(target=run_service, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        for _ in range(0, count, batch_size):
            threads = []
            for _ in range(min(batch_size, count - total_attempts)):
                t = threading.Thread(target=run_service)
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
            run_service()

print(f"[+] Başarılı! {sent_count} SMS gönderildi")
for _ in range(failed_count):
