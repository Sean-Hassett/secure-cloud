# https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_keys(public_exponent, key_size):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('keys/private_key.pem', 'wb') as f:
        f.write(pem)

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('keys/public_key.pem', 'wb') as f:
        f.write(pem)


def encrypt(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt(private_key, message):
    return private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


generate_keys(65537, 2048)
with open('keys/private_key.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
with open('keys/public_key.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

encrypted = encrypt(public_key, b'Hello World!')
decrypted = decrypt(private_key, encrypted)

print(encrypted)
print(decrypted)
