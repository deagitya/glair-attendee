import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management.utils import get_random_secret_key


def generate_encryption_key():
    return Fernet.generate_key().decode("utf-8")


def generate_django_secret_key():
    return get_random_secret_key()


def generate_oidc_rsa_private_key_b64():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


def main():
    credentials_key = generate_encryption_key()
    django_key = generate_django_secret_key()
    oidc_key_b64 = generate_oidc_rsa_private_key_b64()

    print(f"CREDENTIALS_ENCRYPTION_KEY={credentials_key}")
    print(f"DJANGO_SECRET_KEY={django_key}")
    print("AWS_RECORDING_STORAGE_BUCKET_NAME=")
    print("AWS_ACCESS_KEY_ID=")
    print("AWS_SECRET_ACCESS_KEY=")
    print("AWS_DEFAULT_REGION=us-east-1")
    print(f"OIDC_RSA_PRIVATE_KEY_B64={oidc_key_b64}")


if __name__ == "__main__":
    main()
