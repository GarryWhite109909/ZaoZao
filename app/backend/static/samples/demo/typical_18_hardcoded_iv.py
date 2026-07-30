import os
from Crypto.Cipher import AES
from flask import Flask, request

app = Flask(__name__)

SECRET_KEY = b"this_is_a_hardcoded_secret_key_32_byte"[:32]
STATIC_IV = b"fixed_iv_value_16"  # 16 bytes for AES


@app.route("/encrypt")
def encrypt():
    plaintext = request.args.get("data", "")
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, STATIC_IV)
    # PKCS7 填充
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext.encode() + bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex()
