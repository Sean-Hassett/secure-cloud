# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
# https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
# https://cryptography.io/en/

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode


BLOCK_SIZE = 16
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048
PRIVATE_FILE = 'secure_cloud/keys/private_key.pem'
PUBLIC_FILE = 'secure_cloud/keys/public_key.pem'


def generate_symmetric_key():
    key_length = 32
    return os.urandom(key_length)


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    with open(PRIVATE_FILE, "wb") as f:
        f.write(private_pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(PUBLIC_FILE, "wb") as f:
        f.write(public_pem)

    return private_pem, public_pem


def encrypt_sym_key(public_key, sym_key):
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    ret = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

    return b64encode(ret).decode()


def decrypt_sym_key(private_key, encrypted_sym_key):
    return private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


def encrypt_file(symmetric_key, input_file):
    nonce = os.urandom(BLOCK_SIZE)
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CTR(nonce),
        default_backend()
    ).encryptor()

    try:
        in_data = input_file.getvalue()
    except AttributeError:
        in_data = input_file.read()

    out_data = b""
    out_data += nonce
    out_data += encryptor.update(in_data)

    return out_data


def decrypt_file(symmetric_key, in_data):
    nonce = bytes(in_data)[0:BLOCK_SIZE]
    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CTR(nonce),
        default_backend()
    ).decryptor()

    out_data = b""
    out_data += decryptor.update(in_data[BLOCK_SIZE:])

    return out_data
