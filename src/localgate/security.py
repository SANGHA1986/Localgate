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
    _signature_token = None
    _key_cache = {}

    @classmethod
    def _get_signature_token(cls) -> bytes:
        """
        Derives a cryptographic signature token based on LICENSE.md integrity.
        Cached after first resolution — LICENSE.md does not change at runtime.
        """
        if cls._signature_token is not None:
            return cls._signature_token

        license_hash = None
        base_dir = os.path.dirname(os.path.abspath(__file__))

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

        seed = b"SANGHA1986_LocalGate_ZeroTrust_2026_Integrity_Seed"
        h = hashlib.sha256(seed)
        if license_hash:
            h.update(license_hash)
        else:
            h.update(b"fallback_license_missing_token")

        cls._signature_token = h.digest()
        return cls._signature_token

    @classmethod
    def _get_key(cls, salt: bytes) -> tuple:
        """
        Derives 64 bytes of key material from the passphrase/signature and salt using PBKDF2-HMAC-SHA256.
        Returns (K_enc, K_mac). Key material is cached per salt.
        """
        env_key = os.environ.get("LOCALGATE_KEY", "")
        cache_key = (salt, env_key)
        cached = cls._key_cache.get(cache_key)
        if cached is not None:
            return cached

        if env_key:
            passphrase = hashlib.sha256(env_key.encode("utf-8") + cls._get_signature_token()).digest()
        else:
            passphrase = cls._get_signature_token()

        key_material = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=passphrase,
            salt=salt,
            iterations=10000,
            dklen=64
        )
        result = (key_material[:32], key_material[32:])
        cls._key_cache[cache_key] = result
        return result

    @classmethod
    def encrypt(cls, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext bytes and returns authenticated ciphertext.
        Format: salt (16B) + IV (16B) + MAC (32B) + Ciphertext (Variable)
        """
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        k_enc, k_mac = cls._get_key(salt)
        
        # Perform CTR encryption — build keystream then XOR
        block_size = 32
        keystream = bytearray(len(plaintext))
        for i in range(0, len(plaintext), block_size):
            counter_bytes = i.to_bytes(8, byteorder="big")
            keystream_block = hmac.new(k_enc, iv + counter_bytes, hashlib.sha256).digest()
            end = min(i + block_size, len(plaintext))
            keystream[i:end] = keystream_block[: end - i]

        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        
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
            
        # CTR decryption — build keystream then XOR in C-backed bytes()
        block_size = 32
        keystream = bytearray(len(ciphertext))
        for i in range(0, len(ciphertext), block_size):
            counter_bytes = i.to_bytes(8, byteorder="big")
            keystream_block = hmac.new(k_enc, iv + counter_bytes, hashlib.sha256).digest()
            end = min(i + block_size, len(ciphertext))
            keystream[i:end] = keystream_block[: end - i]

        return bytes(a ^ b for a, b in zip(ciphertext, keystream))
