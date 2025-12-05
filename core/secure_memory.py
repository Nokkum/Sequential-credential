import ctypes
import sys
import os
import logging

logger = logging.getLogger('sequential.secure_memory')

try:
    from rust_core import SecureMemory as RustSecureMemory
    RUST_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Rust SecureMemory not available, using Python fallback: {e}")
    RUST_AVAILABLE = False


def secure_erase(byte_arr: bytearray):
    """Attempt to overwrite the contents of a bytearray in place to minimize memory remnants.
    
    Note: Only bytearrays are supported as they are mutable. For bytes objects,
    create a new bytearray first.
    """
    if not isinstance(byte_arr, bytearray):
        raise TypeError("secure_erase only accepts bytearray, not bytes (immutable)")
    
    for i in range(len(byte_arr)):
        byte_arr[i] = 0


def allocate_secure_bytes(size: int) -> bytearray:
    """Return a bytearray intended for temporary sensitive data and attempt to lock pages if possible.

    Note: Python provides limited guarantees. Use this as a best-effort measure.
    """
    if RUST_AVAILABLE:
        try:
            result = RustSecureMemory.allocate_secure_bytes(size)
            return bytearray(result)
        except Exception as e:
            logger.warning(f"Rust allocate_secure_bytes failed, using Python fallback: {e}")
    arr = bytearray(os.urandom(size))
    try:
        if sys.platform.startswith('linux'):
            libc = ctypes.CDLL('libc.so.6')
            libc.mlock(ctypes.c_void_p(id(arr)), ctypes.c_size_t(len(arr)))
    except Exception:
        pass
    return arr


class SecureMemory:
    """Wrapper for Rust SecureMemory class with automatic zeroization.
    
    Note: This provides a Python-friendly interface that accepts bytes directly.
    The Rust implementation provides true memory protection with mlock.
    """
    
    def __init__(self, data: bytes):
        self._initialized = False
        self._use_rust = False
        
        if RUST_AVAILABLE:
            try:
                self._rust = RustSecureMemory(len(data))
                self._rust.write(0, data)
                self._use_rust = True
                self._initialized = True
                return
            except Exception as e:
                logger.warning(f"Rust SecureMemory initialization failed, using Python fallback: {e}")
        
        self._data = bytearray(data)
        self._initialized = True
    
    def get_data(self) -> bytes:
        if self._use_rust:
            return self._rust.as_bytes()
        return bytes(self._data)
    
    def zeroize(self):
        if not self._initialized:
            return
        if self._use_rust:
            self._rust.clear()
        else:
            for i in range(len(self._data)):
                self._data[i] = 0
    
    def __len__(self):
        if self._use_rust:
            return self._rust.len()
        return len(self._data)
    
    def __del__(self):
        if hasattr(self, '_initialized') and self._initialized:
            self.zeroize()
