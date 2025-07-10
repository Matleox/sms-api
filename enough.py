from sms import SendSms
import threading
import traceback

def is_enough(phone, email, count, mode, task_id, task_flags):
    print(f"[TASK {task_id}] Gönderim başladı: {phone} - {count} adet - Mod: {mode}")
    try:
        sms = SendSms(phone, email)
        servisler_sms = []

        for attr in dir(SendSms):
            if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
                servisler_sms.append(attr)

        def run_service(func):
            try:
                print(f"[TASK {task_id}] Servis çalıştırılıyor: {func}")
                getattr(sms, func)()
                print(f"[TASK {task_id}] Servis tamamlandı: {func}")
            except Exception as e:
                print(f"[TASK {task_id}] Hata: {func} => {e}")

        if mode == "turbo":
            for i in range(count):
                if not task_flags.get(task_id, False):
                    print(f"[TASK {task_id}] Gönderim durduruldu (turbo).")
                    break
                threads = []
                for func in servisler_sms:
                    t = threading.Thread(target=run_service, args=(func,))
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join()
        else:
            for i in range(count):
                if not task_flags.get(task_id, False):
                    print(f"[TASK {task_id}] Gönderim durduruldu (normal).")
                    break
                for func in servisler_sms:
                    run_service(func)

        print(f"[TASK {task_id}] Gönderim tamamlandı.")
    except Exception as e:
        print(f"[TASK {task_id}] Genel hata: {e}")
        traceback.print_exc()
