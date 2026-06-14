from cryptography.fernet import Fernet
from app.config import settings
import base64
import os


def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if not key:
        key = os.environ.get("ENCRYPTION_KEY", "")
    if not key:
        raise ValueError("ENCRYPTION_KEY not set. Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()


def encrypt_dict(data: dict, sensitive_keys: list[str] = None) -> dict:
    if sensitive_keys is None:
        sensitive_keys = ["access_token", "refresh_token", "token", "secret", "password", "webhook_secret", "private_key"]
    result = {}
    for k, v in data.items():
        if v and any(sk in k.lower() for sk in sensitive_keys):
            try:
                result[k] = encrypt(str(v))
            except Exception:
                result[k] = v
        else:
            result[k] = v
    return result


def decrypt_dict(data: dict, sensitive_keys: list[str] = None) -> dict:
    if sensitive_keys is None:
        sensitive_keys = ["access_token", "refresh_token", "token", "secret", "password", "webhook_secret", "private_key"]
    result = {}
    for k, v in data.items():
        if v and any(sk in k.lower() for sk in sensitive_keys):
            try:
                result[k] = decrypt(str(v))
            except Exception:
                result[k] = v
        else:
            result[k] = v
    return result
