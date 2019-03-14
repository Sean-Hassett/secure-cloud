# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keys(public_exponent, key_size):
    private_key = rsa.generate_private_key(
    public_exponent=public_exponent,
    key_size=key_size,
    backend=default_backend()
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('keys/private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('keys/public_key.pem', 'wb') as f:
        f.write(pem)


generate_keys(65537, 2048)


