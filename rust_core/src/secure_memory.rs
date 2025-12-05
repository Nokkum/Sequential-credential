use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;
use std::ptr;

#[cfg(unix)]
use libc::{mlock, munlock};

#[pyclass]
pub struct SecureMemory {
    data: Vec<u8>,
    locked: bool,
}

#[pymethods]
impl SecureMemory {
    #[new]
    fn new(size: usize) -> PyResult<Self> {
        let mut data = vec![0u8; size];
        
        #[cfg(unix)]
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut data);
        }
        
        let locked = Self::lock_memory(&data);
        
        Ok(SecureMemory { data, locked })
    }
    
    #[staticmethod]
    fn allocate_secure_bytes(py: Python, size: usize) -> PyResult<PyObject> {
        let mut mem = SecureMemory::new(size)?;
        
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut mem.data);
        
        Ok(PyBytes::new(py, &mem.data).into())
    }
    
    #[staticmethod]
    fn secure_erase(data: &PyBytes) -> PyResult<()> {
        let bytes = data.as_bytes();
        let ptr = bytes.as_ptr() as *mut u8;
        let len = bytes.len();
        
        unsafe {
            ptr::write_bytes(ptr, 0, len);
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
        
        Ok(())
    }
    
    fn write(&mut self, offset: usize, data: &[u8]) -> PyResult<()> {
        if offset + data.len() > self.data.len() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Write would exceed buffer size"
            ));
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
    
    fn read<'py>(&self, py: Python<'py>, offset: usize, length: usize) -> PyResult<&'py PyBytes> {
        if offset + length > self.data.len() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Read would exceed buffer size"
            ));
        }
        Ok(PyBytes::new(py, &self.data[offset..offset + length]))
    }
    
    fn clear(&mut self) {
        self.data.zeroize();
    }
    
    fn is_locked(&self) -> bool {
        self.locked
    }
    
    fn len(&self) -> usize {
        self.data.len()
    }
    
    fn as_bytes<'py>(&self, py: Python<'py>) -> &'py PyBytes {
        PyBytes::new(py, &self.data)
    }
}

impl SecureMemory {
    #[cfg(unix)]
    fn lock_memory(data: &[u8]) -> bool {
        unsafe {
            mlock(data.as_ptr() as *const libc::c_void, data.len()) == 0
        }
    }
    
    #[cfg(not(unix))]
    fn lock_memory(_data: &[u8]) -> bool {
        false
    }
    
    #[cfg(unix)]
    fn unlock_memory(data: &[u8]) {
        unsafe {
            munlock(data.as_ptr() as *const libc::c_void, data.len());
        }
    }
    
    #[cfg(not(unix))]
    fn unlock_memory(_data: &[u8]) {}
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        self.data.zeroize();
        
        if self.locked {
            Self::unlock_memory(&self.data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_memory_creation() {
        let mem = SecureMemory::new(32).unwrap();
        assert_eq!(mem.len(), 32);
    }
    
    #[test]
    fn test_secure_memory_write_read() {
        let mut mem = SecureMemory::new(32).unwrap();
        mem.write(0, b"hello").unwrap();
    }
    
    #[test]
    fn test_secure_memory_clear() {
        let mut mem = SecureMemory::new(32).unwrap();
        mem.write(0, b"secret data").unwrap();
        mem.clear();
        assert!(mem.data.iter().all(|&b| b == 0));
    }
}
