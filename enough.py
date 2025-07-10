from flask import Flask, request, jsonify
import threading
import uuid
from enough import is_enough, stop_task

app = Flask(__name__)

# Her task için durdurma flag'leri burada tutulacak
task_flags = {}

@app.route('/api/sms', methods=['POST'])
def api_sms():
    data = request.get_json()
    phone = data.get('phone')
    email = data.get('email', '')
    count = int(data.get('count', 1))
    mode = data.get('mode', 'normal')

    task_id = uuid.uuid4().hex
    task_flags[task_id] = True  # task aktif, durdurulmadı

    def run_task():
        is_enough(phone, email, count, mode, task_id, task_flags)

        # İş bittiğinde task flag kaldır (temizlik)
        task_flags.pop(task_id, None)

    threading.Thread(target=run_task, daemon=True).start()

    return jsonify({
        'status': 'success',
        'message': f'SMS gönderimi başlatıldı. Task ID: {task_id}',
        'task_id': task_id
    })


@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.get_json()
    task_id = data.get('task_id')

    if task_id in task_flags:
        task_flags[task_id] = False
        return jsonify({'status': 'success', 'message': f'Task {task_id} durduruldu.'})
    else:
        return jsonify({'status': 'error', 'message': 'Task bulunamadı veya zaten durdurulmuş.'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
