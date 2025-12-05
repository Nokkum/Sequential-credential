import os
import base64
import logging
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

logger = logging.getLogger('sequential.crypto_advanced')

try:
    from rust_core import AdvancedCrypto as RustAdvancedCrypto
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust AdvancedCrypto not available, using Python fallback: {e}")
    RUST_AVAILABLE = False


class AdvancedCrypto:
    """Per-provider derived keys and key-wrapping using a master key.

    Master key is the key derived from the master password. For each provider we derive a
    per-provider key (HKDF) and then wrap (encrypt) the per-provider key with the master key.
    
    Uses Rust implementation when available for improved performance.
    """

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self._use_rust = False
        
        if RUST_AVAILABLE:
            try:
                self._rust = RustAdvancedCrypto(master_key)
                self._use_rust = True
                logger.debug("Using Rust AdvancedCrypto")
            except Exception as e:
                logger.warning(f"Rust AdvancedCrypto initialization failed, using Python fallback: {e}")

    def derive_provider_key(self, provider_name: str) -> bytes:
        if self._use_rust:
            try:
                return self._rust.derive_provider_key(provider_name)
            except Exception as e:
                logger.warning(f"Rust derive_provider_key failed, using Python fallback: {e}")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=provider_name.encode('utf-8'),
        )
        return hkdf.derive(self.master_key)

    def wrap_provider_key(self, provider_key: bytes) -> bytes:
        if self._use_rust:
            try:
                return self._rust.wrap_provider_key(provider_key)
            except Exception as e:
                logger.warning(f"Rust wrap_provider_key failed, using Python fallback: {e}")
        return aes_key_wrap(self.master_key[:32], provider_key)

    def unwrap_provider_key(self, wrapped: bytes) -> bytes:
        if self._use_rust:
            try:
                return self._rust.unwrap_provider_key(wrapped)
            except Exception as e:
                logger.warning(f"Rust unwrap_provider_key failed, using Python fallback: {e}")
        return aes_key_unwrap(self.master_key[:32], wrapped)
