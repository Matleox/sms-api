from flask import Flask, request, jsonify
from flask_cors import CORS
from enough import is_enough
import os

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return 'SMS API çalışıyor!'

@app.route('/api/sms', methods=['POST'])
def sms_api():
    try:
        data = request.get_json()
        phone = data.get('phone')
        email = data.get('email', "")
        count = int(data.get('count', 1))
        mode = data.get('mode', 'normal')

        if not phone or len(phone) != 10 or not phone.isdigit():
            return jsonify({'status': 'error', 'message': 'Geçerli bir telefon numarası girin.'}), 400

        result = is_enough(phone, email, count, mode)
        return jsonify({'status': 'success', 'message': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
