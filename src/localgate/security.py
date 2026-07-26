# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import os
import hmac
import hashlib
import secrets

class LocalGateCrypto:
    """
    Pure Python Cryptographically Secure Authenticated Stream Cipher (HMAC-SHA256-CTR + Encrypt-then-MAC).
    Requires ZERO external dependencies to maintain zero-trust integrity.
    """
    
    @classmethod
    def _get_signature_token(cls) -> bytes:
        """
        Derives a cryptographic signature token based on LICENSE.md integrity.
        Ensures licensing validation is cryptographically bound.
        """
        license_hash = None
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Search candidate paths for LICENSE.md
        paths = [
            os.path.join(base_dir, "..", "LICENSE.md"),
            os.path.join(base_dir, "..", "..", "LICENSE.md"),
            os.path.join(os.getcwd(), "LICENSE.md"),
            "LICENSE.md"
        ]
        
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, "rb") as f:
                        license_hash = hashlib.sha256(f.read()).digest()
                        break
                except Exception:
                    pass
                    
        # Derive key combining license hash and project signature
        seed = b"SANGHA1986_LocalGate_ZeroTrust_2026_Integrity_Seed"
        h = hashlib.sha256(seed)
        if license_hash:
            h.update(license_hash)
        else:
            h.update(b"fallback_license_missing_token")
            
        return h.digest()

    @classmethod
    def _get_key(cls, salt: bytes) -> tuple:
        """
        Derives 64 bytes of key material from the passphrase/signature and salt using PBKDF2-HMAC-SHA256.
        Returns (K_enc, K_mac).
        """
        env_key = os.environ.get("LOCALGATE_KEY", "")
        if env_key:
            # Combined mode
            passphrase = hashlib.sha256(env_key.encode("utf-8") + cls._get_signature_token()).digest()
        else:
            # Pure dynamic signature mode
            passphrase = cls._get_signature_token()
            
        # Standard PBKDF2-HMAC key derivation
        key_material = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=passphrase,
            salt=salt,
            iterations=10000,
            dklen=64
        )
        return key_material[:32], key_material[32:]

    @classmethod
    def encrypt(cls, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext bytes and returns authenticated ciphertext.
        Format: salt (16B) + IV (16B) + MAC (32B) + Ciphertext (Variable)
        """
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        k_enc, k_mac = cls._get_key(salt)
        
        # Perform CTR encryption
        ciphertext = bytearray(len(plaintext))
        block_size = 32
        
        for i in range(0, len(plaintext), block_size):
            counter_bytes = i.to_bytes(8, byteorder="big")
            # HMAC-SHA256 as keystream generator (strong CTR emulation)
            keystream_block = hmac.new(k_enc, iv + counter_bytes, hashlib.sha256).digest()
            
            chunk = plaintext[i:i+block_size]
            for j in range(len(chunk)):
                ciphertext[i + j] = chunk[j] ^ keystream_block[j]
                
        ciphertext = bytes(ciphertext)
        
        # Calculate MAC over salt + iv + ciphertext
        mac = hmac.new(k_mac, salt + iv + ciphertext, hashlib.sha256).digest()
        
        return salt + iv + mac + ciphertext

    @classmethod
    def decrypt(cls, data: bytes) -> bytes:
        """
        Decrypts and authenticates ciphertext.
        """
        if len(data) < 64:
            raise ValueError("Ciphertext is too short to be valid LocalGate payload.")
            
        salt = data[:16]
        iv = data[16:32]
        mac = data[32:64]
        ciphertext = data[64:]
        
        k_enc, k_mac = cls._get_key(salt)
        
        # Verify MAC first (Encrypt-then-MAC paradigm)
        expected_mac = hmac.new(k_mac, salt + iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise PermissionError("Security verification failed. LocalGate payload has been tampered or key is incorrect.")
            
        # Perform CTR decryption (symmetric to encryption)
        plaintext = bytearray(len(ciphertext))
        block_size = 32
        
        for i in range(0, len(ciphertext), block_size):
            counter_bytes = i.to_bytes(8, byteorder="big")
            keystream_block = hmac.new(k_enc, iv + counter_bytes, hashlib.sha256).digest()
            
            chunk = ciphertext[i:i+block_size]
            for j in range(len(chunk)):
                plaintext[i + j] = chunk[j] ^ keystream_block[j]
                
        return bytes(plaintext)
