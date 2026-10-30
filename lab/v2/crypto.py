"""Authenticated encryption helpers for local v2 evidence archives."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"WFV2GCM1"
NONCE_SIZE = 12
KEY_SIZE = 32


def key_from_hex(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("BENCHMARK_V2_ENCRYPTION_KEY must be 64 hexadecimal characters") from exc
    if len(key) != KEY_SIZE:
        raise ValueError("BENCHMARK_V2_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def encrypt_file(
    source: Path, destination: Path, key: bytes, *, nonce: bytes | None = None
) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    plaintext = source.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(MAGIC + nonce + ciphertext)


def decrypt_bytes(encrypted: bytes, key: bytes) -> bytes:
    if not encrypted.startswith(MAGIC) or len(encrypted) < len(MAGIC) + NONCE_SIZE + 16:
        raise ValueError("not a valid v2 AES-GCM archive")
    nonce_start = len(MAGIC)
    nonce = encrypted[nonce_start : nonce_start + NONCE_SIZE]
    ciphertext = encrypted[nonce_start + NONCE_SIZE :]
    return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)


def decrypt_file(source: Path, destination: Path, key: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(decrypt_bytes(source.read_bytes(), key))
