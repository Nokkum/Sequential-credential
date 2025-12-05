use pyo3::prelude::*;

mod secure_memory;
mod scanner;
mod security;
mod crypto_advanced;
mod database;
mod validators;

use secure_memory::SecureMemory;
use scanner::{scan_text_for_secrets, scan_files};
use security::EncryptionManager;
use crypto_advanced::AdvancedCrypto;
use database::Database;
use validators::{
    validate_discord_token, 
    validate_github_token,
    validate_openai_token,
    validate_stripe_token,
    validate_slack_token,
};

#[pymodule]
fn rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SecureMemory>()?;
    m.add_class::<EncryptionManager>()?;
    m.add_class::<AdvancedCrypto>()?;
    m.add_class::<Database>()?;
    
    m.add_function(wrap_pyfunction!(scan_text_for_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(scan_files, m)?)?;
    
    m.add_function(wrap_pyfunction!(validate_discord_token, m)?)?;
    m.add_function(wrap_pyfunction!(validate_github_token, m)?)?;
    m.add_function(wrap_pyfunction!(validate_openai_token, m)?)?;
    m.add_function(wrap_pyfunction!(validate_stripe_token, m)?)?;
    m.add_function(wrap_pyfunction!(validate_slack_token, m)?)?;
    
    Ok(())
}
