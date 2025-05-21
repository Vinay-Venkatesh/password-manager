from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64

def generate_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32)

def encrypt_password(password: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    data = base64.b64decode(encrypted_password)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()