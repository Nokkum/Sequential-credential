use pyo3::prelude::*;
use pyo3::types::PyBytes;
use hkdf::Hkdf;
use sha2::Sha256;
use aes_kw::Kek;
use aes::Aes256;
use zeroize::Zeroize;
use parking_lot::RwLock;

#[pyclass]
pub struct AdvancedCrypto {
    master_key: RwLock<Vec<u8>>,
}

#[pymethods]
impl AdvancedCrypto {
    #[new]
    fn new(master_key: &[u8]) -> PyResult<Self> {
        if master_key.len() < 16 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Master key must be at least 16 bytes"
            ));
        }
        
        Ok(AdvancedCrypto {
            master_key: RwLock::new(master_key.to_vec()),
        })
    }
    
    fn derive_provider_key<'py>(&self, py: Python<'py>, provider_name: &str) -> PyResult<&'py PyBytes> {
        let master_key = self.master_key.read();
        
        let hk = Hkdf::<Sha256>::new(None, &master_key);
        let mut okm = [0u8; 32];
        
        hk.expand(provider_name.as_bytes(), &mut okm)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("HKDF expansion failed: {}", e)
            ))?;
        
        Ok(PyBytes::new(py, &okm))
    }
    
    fn wrap_provider_key<'py>(&self, py: Python<'py>, provider_key: &[u8]) -> PyResult<&'py PyBytes> {
        if provider_key.len() != 32 && provider_key.len() != 24 && provider_key.len() != 16 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Provider key must be 16, 24, or 32 bytes"
            ));
        }
        
        let master_key = self.master_key.read();
        let wrapping_key = Self::get_wrapping_key(&master_key)?;
        
        let kek: Kek<Aes256> = Kek::try_from(wrapping_key.as_slice())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid wrapping key: {:?}", e)
            ))?;
        
        let mut wrapped = vec![0u8; provider_key.len() + 8];
        kek.wrap(provider_key, &mut wrapped)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Key wrapping failed: {:?}", e)
            ))?;
        
        Ok(PyBytes::new(py, &wrapped))
    }
    
    fn unwrap_provider_key<'py>(&self, py: Python<'py>, wrapped: &[u8]) -> PyResult<&'py PyBytes> {
        if wrapped.len() < 24 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Wrapped key too short"
            ));
        }
        
        let master_key = self.master_key.read();
        let wrapping_key = Self::get_wrapping_key(&master_key)?;
        
        let kek: Kek<Aes256> = Kek::try_from(wrapping_key.as_slice())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Invalid wrapping key: {:?}", e)
            ))?;
        
        let mut unwrapped = vec![0u8; wrapped.len() - 8];
        kek.unwrap(wrapped, &mut unwrapped)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Key unwrapping failed: {:?}", e)
            ))?;
        
        Ok(PyBytes::new(py, &unwrapped))
    }
    
    fn derive_multiple_keys<'py>(&self, py: Python<'py>, provider_names: Vec<String>) -> PyResult<Vec<&'py PyBytes>> {
        let master_key = self.master_key.read();
        let mut keys = Vec::with_capacity(provider_names.len());
        
        for name in provider_names {
            let hk = Hkdf::<Sha256>::new(None, &master_key);
            let mut okm = [0u8; 32];
            
            hk.expand(name.as_bytes(), &mut okm)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("HKDF expansion failed for {}: {}", name, e)
                ))?;
            
            keys.push(PyBytes::new(py, &okm));
        }
        
        Ok(keys)
    }
    
    fn derive_key_with_context<'py>(
        &self, 
        py: Python<'py>, 
        provider_name: &str,
        context: &str,
        length: usize
    ) -> PyResult<&'py PyBytes> {
        if length > 255 * 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Requested key length too large"
            ));
        }
        
        let master_key = self.master_key.read();
        
        let info = format!("{}:{}", provider_name, context);
        let hk = Hkdf::<Sha256>::new(None, &master_key);
        let mut okm = vec![0u8; length];
        
        hk.expand(info.as_bytes(), &mut okm)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("HKDF expansion failed: {}", e)
            ))?;
        
        Ok(PyBytes::new(py, &okm))
    }
    
    fn update_master_key(&self, new_master_key: &[u8]) -> PyResult<()> {
        if new_master_key.len() < 16 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "New master key must be at least 16 bytes"
            ));
        }
        
        let mut master_key = self.master_key.write();
        master_key.zeroize();
        *master_key = new_master_key.to_vec();
        
        Ok(())
    }
}

impl AdvancedCrypto {
    fn get_wrapping_key(master_key: &[u8]) -> PyResult<Vec<u8>> {
        let len = master_key.len();
        if len >= 32 {
            Ok(master_key[..32].to_vec())
        } else if len >= 24 {
            Ok(master_key[..24].to_vec())
        } else if len >= 16 {
            Ok(master_key[..16].to_vec())
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Master key too short for key wrapping"
            ))
        }
    }
}

impl Drop for AdvancedCrypto {
    fn drop(&mut self) {
        let mut master_key = self.master_key.write();
        master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derive_provider_key() {
        let master_key = [0u8; 32];
        let crypto = AdvancedCrypto::new(&master_key).unwrap();
        
        Python::with_gil(|py| {
            let key1 = crypto.derive_provider_key(py, "provider1").unwrap();
            let key2 = crypto.derive_provider_key(py, "provider2").unwrap();
            
            assert_ne!(key1.as_bytes(), key2.as_bytes());
            
            let key1_again = crypto.derive_provider_key(py, "provider1").unwrap();
            assert_eq!(key1.as_bytes(), key1_again.as_bytes());
        });
    }
    
    #[test]
    fn test_wrap_unwrap_key() {
        let master_key = [0u8; 32];
        let crypto = AdvancedCrypto::new(&master_key).unwrap();
        let provider_key = [1u8; 32];
        
        Python::with_gil(|py| {
            let wrapped = crypto.wrap_provider_key(py, &provider_key).unwrap();
            let unwrapped = crypto.unwrap_provider_key(py, wrapped.as_bytes()).unwrap();
            
            assert_eq!(unwrapped.as_bytes(), &provider_key);
        });
    }
}
