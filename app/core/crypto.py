"""
AES-256-GCM encryption/decryption utilities.
"""
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Returns:
        (ciphertext, iv, tag)  — iv is 12 bytes, tag is 16 bytes.
    """
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag  # 16 bytes
    return ciphertext, iv, tag


def decrypt(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Raises:
        InvalidTag: if the ciphertext or tag has been tampered with.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
