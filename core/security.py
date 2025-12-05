import os
import json
import base64
import getpass
import logging
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime

logger = logging.getLogger('sequential.security')

try:
    from rust_core import EncryptionManager as RustEncryptionManager
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust EncryptionManager not available, using Python fallback: {e}")
    RUST_AVAILABLE = False


class EncryptionManager:
    """Master key management with rotation and lockout support.

    Methods:
    - encrypt/decrypt
    - rotate_master_password(old_pw, new_pw, db, cfg_manager)
    - lockout protection (simple local file tracking)
    
    Uses Rust implementation when available for improved security (Argon2id).
    """

    BASE = '.sequential'
    SALT_FILE = os.path.join(BASE, 'master_salt')
    LOCK_FILE = os.path.join(BASE, 'lockout.json')
    LOCK_THRESHOLD = 5

    def __init__(self, master_password: Optional[str] = None):
        os.makedirs(self.BASE, exist_ok=True)
        
        pwd = master_password or os.environ.get('MASTER_PASSWORD')
        if pwd is None:
            try:
                pwd = getpass.getpass('Enter master password: ')
            except Exception:
                pwd = 'default_master_password'
        
        self._use_rust = False
        self._rust = None
        self.key = self._derive_key(pwd)
        
        if RUST_AVAILABLE:
            try:
                self._rust = RustEncryptionManager(pwd, use_argon2=True)
                self._use_rust = True
                logger.info("Using Rust EncryptionManager with Argon2id")
            except Exception as e:
                logger.warning(f"Rust EncryptionManager initialization failed, using Python fallback: {e}")

    def _derive_key(self, master_password: Optional[str]) -> bytes:
        pwd = master_password or os.environ.get('MASTER_PASSWORD')
        if pwd is None:
            try:
                pwd = getpass.getpass('Enter master password: ')
            except Exception:
                pwd = 'default_master_password'
        pwdb = pwd.encode('utf-8')

        if os.path.exists(self.SALT_FILE):
            salt = open(self.SALT_FILE, 'rb').read()
        else:
            salt = os.urandom(32)
            with open(self.SALT_FILE, 'wb') as f:
                f.write(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300000,
        )
        return base64.urlsafe_b64encode(kdf.derive(pwdb))

    def encrypt(self, plaintext: str) -> bytes:
        if self._use_rust:
            return self._rust.encrypt(plaintext)
        return Fernet(self.key).encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        if self._use_rust:
            return self._rust.decrypt(ciphertext)
        return Fernet(self.key).decrypt(ciphertext).decode('utf-8')

    def _read_lock(self) -> dict:
        try:
            with open(self.LOCK_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {'fails': 0, 'locked_until': None}

    def _write_lock(self, data: dict):
        with open(self.LOCK_FILE, 'w') as f:
            json.dump(data, f)

    def record_failed_attempt(self):
        if self._use_rust:
            try:
                self._rust.record_failed_attempt()
                return
            except Exception as e:
                logger.warning(f"Rust record_failed_attempt failed: {e}")
        data = self._read_lock()
        data['fails'] = data.get('fails', 0) + 1
        if data['fails'] >= self.LOCK_THRESHOLD:
            data['locked_until'] = datetime.utcnow().isoformat()
        self._write_lock(data)

    def is_locked(self) -> bool:
        if self._use_rust:
            try:
                return self._rust.is_locked()
            except Exception as e:
                logger.warning(f"Rust is_locked failed: {e}")
        data = self._read_lock()
        if not data.get('locked_until'):
            return False
        return data.get('fails', 0) >= self.LOCK_THRESHOLD

    def rotate_master_password(self, old_password: str, new_password: str, db, cfg_manager):
        """Re-derive new key and re-encrypt all stored blobs (filesystem + sqlite).

        This operation reads every encrypted blob, decrypts with the old key, then re-encrypts
        with the new key. It must be called with correct old_password.
        """
        old_key = self._derive_key(old_password)
        test_fernet = Fernet(old_key)
        all_meta = db.list_all()
        sample = None
        for cat, entries in all_meta.items():
            for k, meta in entries.items():
                blob = meta.get('blob') or None
                if blob:
                    sample = (cat, k, blob)
                    break
            if sample:
                break

        if sample:
            try:
                base = base64.b64decode(sample[2])
                test_fernet.decrypt(base)
            except Exception as e:
                raise ValueError('Old password verification failed')

        new_salt = os.urandom(32)
        with open(self.SALT_FILE, 'wb') as f:
            f.write(new_salt)

        new_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=new_salt,
            iterations=300000,
        )
        new_key = base64.urlsafe_b64encode(new_kdf.derive(new_password.encode('utf-8')))

        for category, entries in all_meta.items():
            for key_name, meta in entries.items():
                parts = key_name.split('_', 1)
                if len(parts) != 2:
                    continue
                provider, cfg = parts
                blob_entry = db.get_blob_entry(category, provider, cfg)
                if blob_entry and blob_entry.get('blob'):
                    raw = base64.b64decode(blob_entry['blob'])
                    old_plain = Fernet(old_key).decrypt(raw)
                    new_cipher = Fernet(new_key).encrypt(old_plain)
                    db.set_blob(category, provider, cfg, {'blob': base64.b64encode(new_cipher).decode('utf-8')})
        for category in ('tokens', 'apis'):
            enc_dir = os.path.join(cfg_manager.BASE, category, 'encrypted')
            if not os.path.isdir(enc_dir):
                continue
            for fname in os.listdir(enc_dir):
                path = os.path.join(enc_dir, fname)
                try:
                    raw = open(path, 'rb').read()
                    plain = Fernet(old_key).decrypt(raw)
                    new_cipher = Fernet(new_key).encrypt(plain)
                    with open(path, 'wb') as f:
                        f.write(new_cipher)
                except Exception:
                    continue

        self.key = new_key
        if self._use_rust and RUST_AVAILABLE:
            try:
                self._rust = RustEncryptionManager(new_password, use_argon2=True)
            except Exception as e:
                logger.warning(f"Failed to reinitialize Rust EncryptionManager after rotation: {e}")
