from flask import Flask, request, jsonify
from enough import is_enough
from sms import send_sms

app = Flask(__name__)


@app.route('/api/sms', methods=['POST'])
def sms_api():
    data = request.get_json()

    phone = data.get('phone')
    email = data.get('email')
    count = data.get('count')
    mode = data.get('mode')

    if not phone or not count or not mode:
        return jsonify({
            'status': 'error',
            'message': 'Eksik parametre var'
        }), 400

    if not is_enough(phone):
        return jsonify({'status': 'error', 'message': 'Yeterli değil'}), 403

    result = send_sms(phone, count, mode)
    return jsonify({'status': 'success', 'result': result})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Bu satır tüm kaynaklardan gelen isteklere izin verir
