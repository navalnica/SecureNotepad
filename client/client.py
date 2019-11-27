import requests as rq
from base64 import b64encode, b64decode

import rsa
from serpent import Serpent


separator = '\n----------\n'


class Session:

    def __init__(self, url, debug=False):
        self.url = url
        self.debug = debug
        if self.debug:
            print(f'url: "{url}"')

        # args for http methods
        self.args = {'user': 'user', 'password': 'password', 'filename': 'filename'}
    
        self.rsa_private_key = rsa.generate_private_key()
        self.rsa_public_key = rsa.get_public_key(self.rsa_private_key)
        self.rsa_public_pem = rsa.public_key_to_pem(self.rsa_public_key)

        self.serpent_key = None

        self.new_session()


    def receive_serpent_key(self) -> str:
        response = rq.post(
            f'{self.url}/key',
            json={'rsa_public_key': self.rsa_public_pem.decode('utf-8')})
        if response.status_code == 200:
            serpent_key_bytes = rsa.decipher(response.content, self.rsa_private_key)
            return serpent_key_bytes
        else:
            raise Exception(response.json()['error'])
        

    def new_session(self):
        self.serpent_key = self.receive_serpent_key()
        if self.debug:
            print(separator)
            print('received Serpent key:\n%r' % self.serpent_key)
        
        
    def login(self, user, password):
        if self.serpent_key is None:
            self.new_session()
        
        self.user = user
        self.password = password
        self.password_encrypted = Serpent(self.serpent_key).cipher(self.password.encode('utf-8')) # to bytes
        self.password_encrypted = b64encode(self.password_encrypted).decode() # to str suitable for http transmition

        headers = {'Content-type': 'application/octet-stream'}
        if self.debug:
            print(separator)
            print(f'trying to log in to the server.\nuser: "{user}", password: "{password}"')
            print(f'encrypted password: {self.password_encrypted}')
        response = rq.post(
            f'{self.url}/login?{self.args["user"]}={self.user}&{self.args["password"]}={self.password_encrypted}',
            headers=headers
        )
        message = response.json()
        if response.status_code == 200:
            return message['message']
        else:
            raise Exception(message['error'])
        

    def send_text(self, filename, text: str):
        if self.serpent_key is None:
            raise ValueError('serpent_key is None')
        
        headers = {'Content-type': 'application/octet-stream'}
        encrypted_text = Serpent(self.serpent_key).cipher(text.encode('utf-8'))
        if self.debug:
            print(separator)
            print('sending file to server')
            print('raw data:', text)
            print('encrypted text:', encrypted_text)
        response = rq.post(
            f'{self.url}/store?{self.args["user"]}={self.user}&{self.args["password"]}={self.password_encrypted}&{self.args["filename"]}={filename}',
            data=encrypted_text,
            headers=headers)
        message = response.json()
        if response.status_code == 200:
            return message['message']
        elif response.status_code == 401:
            self.serpent_key = None
            return self.send_text(filename, text)
        else:
            raise Exception(message['error'])


    def get_text(self, filename: str):
        if self.serpent_key is None:
            raise ValueError('serpent_key is None')
        
        response = rq.get(
            f'{self.url}/file?{self.args["user"]}={self.user}&{self.args["password"]}={self.password_encrypted}&{self.args["filename"]}={filename}')
        if response.status_code == 200:
            decrypted = Serpent(self.serpent_key).decipher(response.content)
            if self.debug:
                print(separator)
                print('received text from server')
                print('encrypted data:', response.content)
                print('decrypted data:', decrypted)
            return decrypted.decode('utf-8')
        elif response.status_code == 401:
            self.serpent_key = None
            return self.get_text(filename)
        else:
            raise Exception(response.json()['error'])
