from base64 import b64encode, b64decode
import os
import io
import time
from flask import Flask, request, send_file, jsonify
import pyotp


import rsa
from serpent import Serpent


USER = 'user'
FILENAME = 'filename'
PASSWORD = 'password'
TFA_CODE = 'tfa_code'

app = Flask(__name__)
DEBUG = True
users = {'admin': 'password', 'user1': '1111', 'user2': '2222'}
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



@app.route("/")
def hello():
    return "Hello World!"


@app.route("/key", methods=['POST'])
def key():
    remote_addr = request.remote_addr
    if DEBUG:
        print(separator)
        print(f'/key. new session for remote address: {remote_addr}')
    body = request.get_json()
    rsa_client_pub_key_bytes = body['rsa_public_key'].encode('utf-8')
    serpent_cipher = Serpent()
    sessions[remote_addr] = {
        'serpent_key': serpent_cipher.key,
        'time': time.time(),
        'client_rsa_pub': rsa.pem_to_public_key(rsa_client_pub_key_bytes),
        'authorized': False,
        'totp': pyotp.TOTP(pyotp.random_base32())
    }
    serpent_key_bytes = sessions[remote_addr]['serpent_key']
    serpent_key_rsa = rsa.cipher(serpent_key_bytes, sessions[remote_addr]['client_rsa_pub'])
    return send_file(io.BytesIO(serpent_key_rsa), mimetype='application/octet-stream')


def serpent_decipher_wrapper(serpent_key, encoded_b64):
    serpent_cipher = Serpent(serpent_key)
    res = b64decode(encoded_b64)
    res = serpent_cipher.decipher(res)
    res = res.decode()
    return res


@app.route('/login', methods=['POST'])
def login():
    remote_addr = request.remote_addr
    user = request.args.get(USER)
    
    if remote_addr not in sessions:
        return False, (json_message(None, 'server: session is expired'), 401)
    elif user not in users:
        return False, (json_message(None, 'server: no such user'), 400)
    
    password_encrypted = request.args.get(PASSWORD)
    password = serpent_decipher_wrapper(sessions[remote_addr]['serpent_key'], password_encrypted)
    if DEBUG:
        print(separator)
        print(f'user: "{user}", password: "{password}"')
    if not password == users[user]:
        return False, (json_message(None, f'server: wrong password for user "{user}"'), 401)

    tfa_code = sessions[remote_addr]['totp'].now()
    print(f'2fa code for {remote_addr}: "{tfa_code}". valid for 30 seconds')

    return json_message(f'server: login succeeded'), 200


@app.route('/tfa', methods=['POST'])
def tfa():
    remote_addr = request.remote_addr
    user = request.args.get(USER)
    
    if remote_addr not in sessions:
        return False, (json_message(None, 'server: session is expired'), 401)
    elif user not in users:
        return False, (json_message(None, 'server: no such user'), 400)
    
    password_encrypted = request.args.get(PASSWORD)
    password = serpent_decipher_wrapper(sessions[remote_addr]['serpent_key'], password_encrypted)
    if DEBUG:
        print(separator)
        print(f'user: "{user}", password: "{password}"')
    if not password == users[user]:
        return False, (json_message(None, f'server: wrong password for user "{user}"'), 401)

    tfa_code_encrypted = request.args.get(TFA_CODE)
    tfa_code = serpent_decipher_wrapper(sessions[remote_addr]['serpent_key'], tfa_code_encrypted)
    success = sessions[remote_addr]['totp'].verify(tfa_code)
    if DEBUG:
        print(f'received tfa code "{tfa_code}" from {remote_addr}')
        print(f'2fa succeeded: {success}')
    if not success:
        return json_message(None, f'server: wrong 2fa code received'), 401 

    sessions[remote_addr]['authorized'] = True   

    return json_message(f'server: 2fa succeeded'), 200



@app.route("/store", methods=['POST'])
def store():
    remote_addr = request.remote_addr
    if not sessions[remote_addr]['authorized']:
        return json_message(None, f'server: not authorized request from {remote_addr}'), 401

    request_filename = request.args.get(FILENAME)
    data = request.data
    serpent_cipher = Serpent(sessions[remote_addr]['serpent_key'])
    decrypted = serpent_cipher.decipher(data)
    if DEBUG:
        print(separator)
        print('Got data: ', data)
        print('Decrypted: ', decrypted)
        print(f'Saving data to file {request_filename}')
    store_file(request_filename, decrypted.decode('utf-8'))
    return json_message(f'server: file {request_filename} is successfully saved'), 200


@app.route("/file", methods=['GET'])
def file():
    remote_addr = request.remote_addr
    if not sessions[remote_addr]['authorized']:
        return json_message(None, f'server: not authorized request from {remote_addr}'), 401

    request_filename = request.args.get(FILENAME)
    serpent_cipher = Serpent(sessions[remote_addr]['serpent_key'])
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
