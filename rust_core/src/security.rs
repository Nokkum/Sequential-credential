use pyo3::prelude::*;
use pyo3::types::PyBytes;
use argon2::Argon2;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use std::fs;
use std::path::Path;
use parking_lot::Mutex;
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

const BASE_DIR: &str = ".sequential";
const SALT_FILE: &str = ".sequential/master_salt";
const LOCK_FILE: &str = ".sequential/lockout.json";
const LOCK_THRESHOLD: u32 = 5;
const PBKDF2_ITERATIONS: u32 = 300_000;
const ARGON2_MEMORY_COST: u32 = 65536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, Serialize, Deserialize)]
struct LockState {
    fails: u32,
    locked_until: Option<String>,
}

impl Default for LockState {
    fn default() -> Self {
        LockState {
            fails: 0,
            locked_until: None,
        }
    }
}

#[pyclass]
pub struct EncryptionManager {
    key: Mutex<Vec<u8>>,
    use_argon2: bool,
}

#[pymethods]
impl EncryptionManager {
    #[new]
    #[pyo3(signature = (master_password=None, use_argon2=true))]
    fn new(master_password: Option<&str>, use_argon2: bool) -> PyResult<Self> {
        fs::create_dir_all(BASE_DIR).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to create base dir: {}", e))
        })?;
        
        let password = master_password
            .map(|s| s.to_string())
            .or_else(|| std::env::var("MASTER_PASSWORD").ok())
            .unwrap_or_else(|| "default_master_password".to_string());
        
        let key = if use_argon2 {
            Self::derive_key_argon2(&password)?
        } else {
            Self::derive_key_pbkdf2(&password)?
        };
        
        Ok(EncryptionManager {
            key: Mutex::new(key),
            use_argon2,
        })
    }
    
    fn encrypt<'py>(&self, py: Python<'py>, plaintext: &str) -> PyResult<&'py PyBytes> {
        let key = self.key.lock();
        let cipher = Aes256Gcm::new_from_slice(&key[..32])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key: {}", e)))?;
        
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Encryption failed: {}", e)))?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(PyBytes::new(py, &result))
    }
    
    fn decrypt(&self, ciphertext: &[u8]) -> PyResult<String> {
        if ciphertext.len() < 12 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Ciphertext too short"
            ));
        }
        
        let key = self.key.lock();
        let cipher = Aes256Gcm::new_from_slice(&key[..32])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid key: {}", e)))?;
        
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let plaintext = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Decryption failed: {}", e)))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid UTF-8: {}", e)))
    }
    
    fn encrypt_base64(&self, plaintext: &str) -> PyResult<String> {
        Python::with_gil(|py| {
            let encrypted = self.encrypt(py, plaintext)?;
            Ok(URL_SAFE.encode(encrypted.as_bytes()))
        })
    }
    
    fn decrypt_base64(&self, ciphertext_b64: &str) -> PyResult<String> {
        let ciphertext = URL_SAFE.decode(ciphertext_b64)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid base64: {}", e)))?;
        self.decrypt(&ciphertext)
    }
    
    fn record_failed_attempt(&self) -> PyResult<()> {
        let mut state = Self::read_lock_state();
        state.fails += 1;
        
        if state.fails >= LOCK_THRESHOLD {
            state.locked_until = Some(Utc::now().to_rfc3339());
        }
        
        Self::write_lock_state(&state)?;
        Ok(())
    }
    
    fn is_locked(&self) -> bool {
        let state = Self::read_lock_state();
        
        if state.fails < LOCK_THRESHOLD {
            return false;
        }
        
        if let Some(locked_until_str) = &state.locked_until {
            if let Ok(locked_until) = DateTime::parse_from_rfc3339(locked_until_str) {
                let lock_duration = chrono::Duration::minutes(5);
                let unlock_time = locked_until + lock_duration;
                return Utc::now() < unlock_time.with_timezone(&Utc);
            }
        }
        
        state.fails >= LOCK_THRESHOLD
    }
    
    fn reset_lockout(&self) -> PyResult<()> {
        Self::write_lock_state(&LockState::default())
    }
    
    fn rotate_master_password(&mut self, old_password: &str, new_password: &str) -> PyResult<()> {
        let old_key = if self.use_argon2 {
            Self::derive_key_argon2(old_password)?
        } else {
            Self::derive_key_pbkdf2(old_password)?
        };
        
        {
            let current_key = self.key.lock();
            if *current_key != old_key {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Old password verification failed"
                ));
            }
        }
        
        let mut new_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_salt);
        fs::write(SALT_FILE, &new_salt)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to write salt: {}", e)))?;
        
        let new_key = if self.use_argon2 {
            Self::derive_key_argon2_with_salt(new_password, &new_salt)?
        } else {
            Self::derive_key_pbkdf2_with_salt(new_password, &new_salt)?
        };
        
        let mut key = self.key.lock();
        key.zeroize();
        *key = new_key;
        
        Ok(())
    }
    
    fn get_key_bytes<'py>(&self, py: Python<'py>) -> &'py PyBytes {
        let key = self.key.lock();
        PyBytes::new(py, &key)
    }
    
    #[getter]
    fn key<'py>(&self, py: Python<'py>) -> &'py PyBytes {
        self.get_key_bytes(py)
    }
}

impl EncryptionManager {
    fn get_or_create_salt() -> PyResult<Vec<u8>> {
        if Path::new(SALT_FILE).exists() {
            fs::read(SALT_FILE)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read salt: {}", e)))
        } else {
            let mut salt = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            fs::write(SALT_FILE, &salt)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to write salt: {}", e)))?;
            Ok(salt)
        }
    }
    
    fn derive_key_pbkdf2(password: &str) -> PyResult<Vec<u8>> {
        let salt = Self::get_or_create_salt()?;
        Self::derive_key_pbkdf2_with_salt(password, &salt)
    }
    
    fn derive_key_pbkdf2_with_salt(password: &str, salt: &[u8]) -> PyResult<Vec<u8>> {
        let mut key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        );
        Ok(key)
    }
    
    fn derive_key_argon2(password: &str) -> PyResult<Vec<u8>> {
        let salt = Self::get_or_create_salt()?;
        Self::derive_key_argon2_with_salt(password, &salt)
    }
    
    fn derive_key_argon2_with_salt(password: &str, salt: &[u8]) -> PyResult<Vec<u8>> {
        let params = argon2::Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(32),
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid Argon2 params: {}", e)))?;
        
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        
        let mut key = vec![0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Argon2 hashing failed: {}", e)))?;
        
        Ok(key)
    }
    
    fn read_lock_state() -> LockState {
        if let Ok(content) = fs::read_to_string(LOCK_FILE) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            LockState::default()
        }
    }
    
    fn write_lock_state(state: &LockState) -> PyResult<()> {
        let json = serde_json::to_string(state)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON serialization failed: {}", e)))?;
        fs::write(LOCK_FILE, json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to write lock file: {}", e)))
    }
}

impl Drop for EncryptionManager {
    fn drop(&mut self) {
        let mut key = self.key.lock();
        key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let manager = EncryptionManager::new(Some("test_password"), false).unwrap();
        let plaintext = "Hello, World!";
        let encrypted = manager.encrypt_base64(plaintext).unwrap();
        let decrypted = manager.decrypt_base64(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_lockout() {
        let manager = EncryptionManager::new(Some("test_password"), false).unwrap();
        assert!(!manager.is_locked());
    }
}
