from base64 import b64encode, b64decode
import os
import io
import time
from flask import Flask, request, send_file, jsonify


import rsa
from serpent import Serpent


USER = 'user'
FILENAME = 'filename'
PASSWORD = 'password'

app = Flask(__name__)
DEBUG = True
users = {'admin': 'password'}
sessions = {}
storage = {}

separator = '\n----------\n'


def json_message(message, error=None):
    return jsonify(message=message, error=error)


def get_file(name):
    fp = f'server/data/{name}'
    if not os.path.isfile(fp):
        with open(fp, 'w') as fout:
            pass
    with open(fp, 'r') as fin:
        return ''.join(fin)


def store_file(name, data):
    with open(f'server/data/{name}', 'w') as fout:
        fout.write(data)


def check_session_user_and_password(request):
    remote_address = request.remote_addr
    user = request.args.get(USER)
    
    if remote_address not in sessions:
        return False, (json_message(None, 'Session is expired.'), 401)
    elif user not in users:
        return False, (json_message(None, 'No such user.'), 400)
    
    password_encrypted = request.args.get(PASSWORD)
    serpent_cipher = Serpent(sessions[remote_address]['serpent_key'])
    password = b64decode(password_encrypted)
    password = serpent_cipher.decipher(password)
    password = password.decode()
    if DEBUG:
        print(separator)
        print(f'user: "{user}", password: "{password}"')
    if not password == users[user]:
        return False, (json_message(None, f'Wrong password for user "{user}"'), 401)

    return True, None


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/key", methods=['POST'])
def key():
    remote_address = request.remote_addr
    if DEBUG:
        print(separator)
        print(f'/key. new session for remote address: {remote_address}')
    body = request.get_json()
    rsa_client_pub_key_bytes = body['rsa_public_key'].encode('utf-8')
    serpent_cipher = Serpent()
    sessions[remote_address] = {
        'serpent_key': serpent_cipher.key,
        'time': time.time(),
        'client_rsa_pub': rsa.pem_to_public_key(rsa_client_pub_key_bytes)
    }
    serpent_key_bytes = sessions[remote_address]['serpent_key']
    serpent_key_rsa = rsa.cipher(serpent_key_bytes, sessions[remote_address]['client_rsa_pub'])
    return send_file(io.BytesIO(serpent_key_rsa), mimetype='application/octet-stream')


@app.route('/login', methods=['POST'])
def login():
    ok, return_val = check_session_user_and_password(request)
    if not ok: return return_val    
    return json_message(f'Login succeeded'), 200



@app.route("/store", methods=['POST'])
def store():
    ok, return_val = check_session_user_and_password(request)
    if not ok: return return_val

    remote_address = request.remote_addr
    request_filename = request.args.get(FILENAME)
    data = request.data
    serpent_cipher = Serpent(sessions[remote_address]['serpent_key'])
    decrypted = serpent_cipher.decipher(data)
    if DEBUG:
        print(separator)
        print('Got data: ', data)
        print('Decrypted: ', decrypted)
        print(f'Saving data to file {request_filename}')
    store_file(request_filename, decrypted.decode('utf-8'))
    return json_message(f'File {request_filename} is successfully saved'), 200


@app.route("/file", methods=['GET'])
def file():
    ok, return_val = check_session_user_and_password(request)
    if not ok: return return_val

    remote_address = request.remote_addr
    request_filename = request.args.get(FILENAME)
    serpent_cipher = Serpent(sessions[remote_address]['serpent_key'])
    raw = get_file(request_filename)
    raw_bytes = raw.encode('utf-8')
    data = serpent_cipher.cipher(raw_bytes)
    if DEBUG:
        print(separator)
        print('Raw data: ', raw)
        print('Encrypted: ', data)
    return send_file(io.BytesIO(data), mimetype='application/octet-stream')


if __name__ == "__main__":
    app.run()
