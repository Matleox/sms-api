from sms import SendSms

def is_enough(phone, email, count, mode):
    sms = SendSms(phone, email)
    servisler_sms = []

    for attr in dir(SendSms):
        if callable(getattr(SendSms, attr)) and not attr.startswith('__'):
            servisler_sms.append(attr)

    if mode == "turbo":
        import threading
        threads = []
        for _ in range(count):
            for func in servisler_sms:
                t = threading.Thread(target=getattr(sms, func))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
    else:
        for _ in range(count):
            for func in servisler_sms:
                getattr(sms, func)()

    return f"{count} adet SMS {mode} modunda gönderildi."
