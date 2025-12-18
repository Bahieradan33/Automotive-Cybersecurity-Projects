"""
UDS Security Access Tool - Core Security Functions

Module: security_access.py
PURPOSE:
- SEED Generation
- KEY Derivation using HMAC-SHA256
- Small, testable functions used by ECU simulations and UDS client tools.

Notes from author:
- This project uses a demo algorithm (HMAC-SHA256) for educational purposes.
- Real-world ECUs may use proprietary or more complex algorithms.
- Not intended for real vehicle exploitation or unauthorised access.

"""

from __future__ import annotations

import hmac
import hashlib
import secrets
from dataclasses import dataclass



def generate_seed(length: int = 4) -> bytes:
    """
    Generate a random seed of specified length in bytes.
    Real ECUs often use 2/4/8/16 bytes for seed values.
    we use 4 for this demo tool.
    
    """
    if length <= 0:
        raise ValueError("Length must be >0")
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time to prevent timing mismatch.
    """
    return hmac.compare_digest(a, b)


def derive_key_hmac_sha256(seed: bytes, secret: bytes, out_length: int = 4) -> bytes:
    """Derive a key using HMAC-SHA256 from the given seed and secret.
    
    The output length can be specified (default is 4 bytes).
    """
    if not seed:
        raise ValueError("Seed must be provided.")
    if not secret:
        raise ValueError("Secret must be provided.")
    if out_length <= 0 or out_length > 32:
        raise ValueError("Output length must be between 1 and 32 bytes")
    
    h = hmac.new(secret, seed, hashlib.sha256)
    derived_key = h.digest()[:out_length]
    return derived_key

@dataclass(frozen=True) 
class SecurityLevelConfig:
    """Define security level configurations for UDS security access."""

    level: int
    seed_length: int
    key_length: int
    algorithm: str  
