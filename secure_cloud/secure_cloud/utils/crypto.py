import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode


BLOCK_SIZE = 16
SYMMETRIC_KEY_LENGTH = 32
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048
PRIVATE_FILE = 'secure_cloud/keys/private_key.pem'
PUBLIC_FILE = 'secure_cloud/keys/public_key.pem'


def generate_symmetric_key():
    # use cryptographically strong, OS-specific pseudo-random number generator to create key
    return os.urandom(SYMMETRIC_KEY_LENGTH)


def generate_key_pair():
    # generate 2048 bit private key
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend())

    # serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    # write the PEM private key to local storage
    with open(PRIVATE_FILE, "wb") as f:
        f.write(private_pem)

    # retrieve the public key from the private key
    public_key = private_key.public_key()

    # serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # write the PEM private key to local storage
    with open(PUBLIC_FILE, "wb") as f:
        f.write(public_pem)

    # return the private and public key in PEM format
    return private_pem, public_pem


def encrypt_sym_key(public_key, sym_key):
    # load the public key from the passed in PEM public key
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )

    # use the public key to encrypt the symmetric key using MGF1 mask generation function and SHA256 hashing algorithm
    ret = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

    # convert encrypted symmetric key to UTF-8 for serialization to JSON
    return b64encode(ret).decode()


def decrypt_sym_key(private_key, encrypted_sym_key):
    # use the private key to decrypt the symmetric key using MGF1 mask generation function and SHA256 hashing algorithm
    return private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


def encrypt_file(symmetric_key, input_file):
    # generate random 16-byte nonce using OS-specific pseudo-random number generator
    nonce = os.urandom(BLOCK_SIZE)
    # create an encryptor object using AES encryption algorithm, Counter (CTR) mode, the symmetric key and the nonce.
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CTR(nonce),
        default_backend()
    ).encryptor()

    # file is read in as different object types depending on file extension and size. May not be fully tested but works
    # with typical formats such as .txt, .pdf and .mp4
    try:
        in_data = input_file.getvalue()
    except AttributeError:
        in_data = input_file.read()

    # prepare stream of bytes as output
    out_data = b""
    # write the nonce in plaintext to the start of the return for use in decrypting later
    out_data += nonce
    # write the encrypted contents to the output
    out_data += encryptor.update(in_data)

    return out_data


def decrypt_file(symmetric_key, in_data):
    # retrieve the nonce from the first 16 bytes of the encrypted contents
    nonce = bytes(in_data)[0:BLOCK_SIZE]
    # create a decryptor object using AES encryption algorithm, Counter (CTR) mode, the symmetric key and the nonce.
    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.CTR(nonce),
        default_backend()
    ).decryptor()

    # prepare stream of bytes as output
    out_data = b""
    # write the decrypted contents to the output
    out_data += decryptor.update(in_data[BLOCK_SIZE:])

    return out_data
