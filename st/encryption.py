# -*- coding: utf-8 -*-
"""
Created on Mon Nov 18 13:50:14 2024

@author: 80816
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256
import base64
import json


class AESCipher:
    def __init__(self, password):
        self.key = sha256(password.encode()).digest()

    def encrypt(self, plaintext):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt(self, ciphertext):
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()


class RSACipher:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.private_key = self.key

    def encrypt(self, plaintext):
        cipher = PKCS1_OAEP.new(self.public_key)
        return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()


class SHA256Hasher:
    def hash_password(self, password):
        return sha256(password.encode()).hexdigest()


def save_to_file(content, filename):
    with open(filename, 'w') as f:
        f.write(content)
