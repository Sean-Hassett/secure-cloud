# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
# https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
# https://cryptography.io/en/

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


CHUNK_SIZE = 64*1024
BLOCK_SIZE = 16


def generate_symmetric_key():
    key_length = 32
    # generate key using cryptographically secure pseudo-random number generator
    secret_key = os.urandom(key_length)
    return secret_key


def generate_keys(public_exponent, key_size, private_file, public_file):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend())

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    with open(private_file, "wb") as f:
        f.write(pem)

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(public_file, "wb") as f:
        f.write(pem)


def encrypt_sym_key(public_key, sym_key):
    return public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


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

    in_data = input_file.getvalue()
    out_data = ""
    out_data += str(nonce)

    for i in range(0, len(in_data), CHUNK_SIZE):
        chunk = in_data[i:i + CHUNK_SIZE]
        out_data += str(encryptor.update(chunk))
    return out_data


def decrypt_file(symmetric_key, input_file):
    nonce = input_file[0:BLOCK_SIZE]
    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CBC(nonce),
        backend=default_backend()
    ).decryptor()

    in_data = input_file.read()
    out_data = ""

    for i in range(CHUNK_SIZE, len(in_data), CHUNK_SIZE):
        chunk = in_data[i:i + CHUNK_SIZE]
        out_data += str(decryptor.update(chunk))

    return out_data
