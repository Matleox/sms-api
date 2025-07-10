from sms import SendSms
import threading

def is_enough(phone, email, count, mode, task_id, task_flags):
    sms = SendSms(phone, email)
    servisler_sms = []

    for attr in dir(SendSms):
        if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
            servisler_sms.append(attr)

    def run_service(func):
        try:
            getattr(sms, func)()
        except Exception:
            pass  # hata olsa da devam et

    if mode == "turbo":
        for i in range(count):
            if not task_flags.get(task_id, False):  # Durdurulmuş mu kontrolü
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
            if not task_flags.get(task_id, False):  # Durdurulmuş mu kontrolü
                break
            for func in servisler_sms:
                run_service(func)

    return f"{count} adet SMS {mode} modunda gönderildi."
