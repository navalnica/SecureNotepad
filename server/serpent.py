import numpy as np
from CryptoPlus.Cipher import python_Serpent


class Serpent:
    def __init__(self, key=None, IV=None, segment_size=16):
        self.key = key or self.generate_random_key()
        self.cipher_obj = python_Serpent.new(self.key, python_Serpent.MODE_CFB, IV, segment_size=segment_size)
        self.decipher_obj = python_Serpent.new(self.key, python_Serpent.MODE_CFB, IV, segment_size=segment_size)


    def generate_random_key(self, bits_cnt=128):
        nums = np.random.randint(256, size=(bits_cnt // 16))
        key = ''.join(['{:02x}'.format(x).upper() for x in nums])
        key = key.encode('utf-8')
        return key


    def cipher(self, plaintext):
        ciphertext = self.cipher_obj.encrypt(plaintext)
        return ciphertext


    def decipher(self, ciphertext):
        deciphered = self.decipher_obj.decrypt(ciphertext)
        return deciphered