import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _get_key(password: str, salt: bytes) -> bytes:
    """Generate a key for Fernet."""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt(text: str, password: str, encoding='utf-8') -> bytes:
    """Encrypt a string."""

    # salt:
    salt = os.urandom(16)
    key = _get_key(password, salt)

    # encrypt:
    f = Fernet(key)
    encrypted_data = f.encrypt(text.encode(encoding=encoding))
    return salt + encrypted_data


def decrypt(encrypted: bytes, password: str, encoding='utf-8') -> str:
    """Decrypt a string."""

    # separate the salt from the encrypted content:
    salt, encrypted = encrypted[:16], encrypted[16:]

    # decrypt:
    key = _get_key(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode(encoding=encoding)
