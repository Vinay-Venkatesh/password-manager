import base64
import random
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import bcrypt

class Encryption:
    ## Generate encryption key
    def get_encryption_key(self, master_password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000000,
            backend=default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    ## Password encryption
    def encrypt_password(self, password, key):
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password

    ## To generate random passwords
    def generate_randam_password(self, length=12):
        char_pool = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(char_pool) for char in range(length))
        return password

class Decryption:
    ## Password decryption
    def decrypt_password(self, encrypted_password, key):
        fernet = Fernet(key)
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password

# def generate_secure_password(_password):
#     salt = os.urandom(16)
#     iterations = 100_000
#     hash_value = hashlib.pbkdf2_hmac(
#         'sha256',
#         _password.encode('utf-8'),
#         salt,
#         iterations
#     )
#     password_hash = salt + hash_value
#     return password_hash

def generate_secure_password(_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(_password.encode('utf-8'), salt)
    return hashed