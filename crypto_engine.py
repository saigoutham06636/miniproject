import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
_SALT_SIZE = 16  # bytes
_NONCE_SIZE = 12  # bytes for AESGCM
_KDF_ITERATIONS = 200_000
_KEY_SIZE = 32  # 256-bit AES


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the given password and salt using PBKDF2-HMAC-SHA256."""
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password_bytes)


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file with AES-256-GCM.

    File format:
        [16 bytes salt][12 bytes nonce][ciphertext+tag]
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a file produced by encrypt_file using the same password."""
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < _SALT_SIZE + _NONCE_SIZE:
        raise ValueError("Encrypted file is too short or corrupted.")

    salt = data[:_SALT_SIZE]
    nonce = data[_SALT_SIZE:_SALT_SIZE + _NONCE_SIZE]
    ciphertext = data[_SALT_SIZE + _NONCE_SIZE :]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(plaintext)
