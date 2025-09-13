#!/usr/bin/env python3
"""
Cryptographic utilities for Quantum-Safe VPN
Implements hybrid key exchange and encryption
"""

import os
import hmac
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import oqs

# Protocol constants
KYBER_VARIANT = "Kyber768"
DILITHIUM_VARIANT = "Dilithium3"
HKDF_SALT = b"qsafe-vpn-2024"
HKDF_INFO = b"session"
SESSION_KEY_LENGTH = 32
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTH = 16

class CryptoError(Exception):
    """Custom exception for crypto operations"""
    pass

class QuantumSafeCrypto:
    """Quantum-safe cryptographic operations"""
    
    @staticmethod
    def generate_kyber_keypair() -> Tuple[bytes, bytes]:
        """Generate Kyber KEM keypair"""
        try:
            kem = oqs.KeyEncapsulation(KYBER_VARIANT)
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
        except Exception as e:
            raise CryptoError(f"Kyber keypair generation failed: {e}")
    
    @staticmethod
    def generate_dilithium_keypair() -> Tuple[bytes, bytes]:
        """Generate Dilithium signature keypair"""
        try:
            sig = oqs.Signature(DILITHIUM_VARIANT)
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return public_key, secret_key
        except Exception as e:
            raise CryptoError(f"Dilithium keypair generation failed: {e}")
    
    @staticmethod
    def generate_x25519_keypair() -> Tuple[X25519PublicKey, X25519PrivateKey]:
        """Generate ephemeral X25519 keypair"""
        try:
            private_key = X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return public_key, private_key
        except Exception as e:
            raise CryptoError(f"X25519 keypair generation failed: {e}")
    
    @staticmethod
    def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate secret using Kyber public key"""
        try:
            kem = oqs.KeyEncapsulation(KYBER_VARIANT)
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
        except Exception as e:
            raise CryptoError(f"Kyber encapsulation failed: {e}")
    
    @staticmethod
    def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate secret using Kyber secret key"""
        try:
            kem = oqs.KeyEncapsulation(KYBER_VARIANT)
            kem.set_secret_key(secret_key)
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise CryptoError(f"Kyber decapsulation failed: {e}")
    
    @staticmethod
    def dilithium_sign(secret_key: bytes, message: bytes) -> bytes:
        """Sign message with Dilithium secret key"""
        try:
            sig = oqs.Signature(DILITHIUM_VARIANT)
            sig.set_secret_key(secret_key)
            signature = sig.sign(message)
            return signature
        except Exception as e:
            raise CryptoError(f"Dilithium signing failed: {e}")
    
    @staticmethod
    def dilithium_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify Dilithium signature"""
        try:
            sig = oqs.Signature(DILITHIUM_VARIANT)
            return sig.verify(message, signature, public_key)
        except Exception as e:
            return False
    
    @staticmethod
    def x25519_exchange(private_key: X25519PrivateKey, peer_public_key_bytes: bytes) -> bytes:
        """Perform X25519 key exchange"""
        try:
            peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
            shared_secret = private_key.exchange(peer_public_key)
            return shared_secret
        except Exception as e:
            raise CryptoError(f"X25519 exchange failed: {e}")
    
    @staticmethod
    def derive_session_key(kyber_secret: bytes, x25519_secret: bytes) -> bytes:
        """Derive session key from hybrid shared secrets using HKDF"""
        try:
            # Combine both shared secrets
            combined_secret = kyber_secret + x25519_secret
            
            # Derive session key using HKDF-SHA256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=SESSION_KEY_LENGTH,
                salt=HKDF_SALT,
                info=HKDF_INFO,
            )
            session_key = hkdf.derive(combined_secret)
            return session_key
        except Exception as e:
            raise CryptoError(f"Session key derivation failed: {e}")

class SessionCrypto:
    """Session encryption/decryption using AES-256-GCM"""
    
    def __init__(self, session_key: bytes, session_id: bytes):
        """Initialize with session key and ID"""
        if len(session_key) != SESSION_KEY_LENGTH:
            raise CryptoError(f"Invalid session key length: {len(session_key)}")
        
        self.aead = AESGCM(session_key)
        self.session_id = session_id
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with AES-256-GCM"""
        try:
            # Generate random nonce
            nonce = os.urandom(GCM_NONCE_LENGTH)
            
            # Use session ID as Additional Authenticated Data (AAD)
            ciphertext = self.aead.encrypt(nonce, plaintext, self.session_id)
            
            # Return nonce + ciphertext (ciphertext includes auth tag)
            return nonce + ciphertext
        except Exception as e:
            raise CryptoError(f"Encryption failed: {e}")
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with AES-256-GCM"""
        try:
            if len(data) < GCM_NONCE_LENGTH + GCM_TAG_LENGTH:
                raise CryptoError("Invalid encrypted data length")
            
            # Extract nonce and ciphertext
            nonce = data[:GCM_NONCE_LENGTH]
            ciphertext = data[GCM_NONCE_LENGTH:]
            
            # Decrypt with session ID as AAD
            plaintext = self.aead.decrypt(nonce, ciphertext, self.session_id)
            return plaintext
        except Exception as e:
            raise CryptoError(f"Decryption failed: {e}")

def save_key_to_file(key_data: bytes, filename: str) -> None:
    """Save key data to PEM file"""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'wb') as f:
            f.write(key_data)
        os.chmod(filename, 0o600)  # Restrict permissions
    except Exception as e:
        raise CryptoError(f"Failed to save key to {filename}: {e}")

def load_key_from_file(filename: str) -> bytes:
    """Load key data from PEM file"""
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except Exception as e:
        raise CryptoError(f"Failed to load key from {filename}: {e}")

def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of byte strings"""
    return hmac.compare_digest(a, b)

def truncate_hex(data: bytes, max_len: int = 16) -> str:
    """Convert bytes to truncated hex string for logging"""
    hex_str = data.hex()
    if len(hex_str) > max_len:
        return hex_str[:max_len] + "..."
    return hex_str