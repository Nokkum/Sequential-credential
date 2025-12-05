use pyo3::prelude::*;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use std::time::Duration;
use serde::Deserialize;

const DEFAULT_TIMEOUT: u64 = 5;

#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: String,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
    id: u64,
}

fn create_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
}

#[pyfunction]
#[pyo3(signature = (token, timeout=None))]
pub fn validate_discord_token(token: &str, timeout: Option<u64>) -> (bool, String) {
    let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
    
    let client = match create_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to create HTTP client: {}", e)),
    };
    
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bot {}", token);
    
    match HeaderValue::from_str(&auth_value) {
        Ok(v) => headers.insert(AUTHORIZATION, v),
        Err(e) => return (false, format!("Invalid token format: {}", e)),
    };
    
    match client
        .get("https://discord.com/api/v10/users/@me")
        .headers(headers)
        .send()
    {
        Ok(response) => {
            match response.status().as_u16() {
                200 => {
                    match response.json::<DiscordUser>() {
                        Ok(user) => (true, format!("Valid token for user: {}#{}", user.username, user.discriminator)),
                        Err(_) => (true, "Valid token".to_string()),
                    }
                }
                401 => (false, "Unauthorized (invalid token)".to_string()),
                403 => (false, "Forbidden (token lacks permissions)".to_string()),
                429 => (false, "Rate limited - try again later".to_string()),
                status => (false, format!("Unexpected status: {}", status)),
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "Request timed out".to_string())
            } else if e.is_connect() {
                (false, "Connection failed".to_string())
            } else {
                (false, format!("Network error: {}", e))
            }
        }
    }
}

#[pyfunction]
#[pyo3(signature = (token, timeout=None))]
pub fn validate_github_token(token: &str, timeout: Option<u64>) -> (bool, String) {
    let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
    
    let client = match create_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to create HTTP client: {}", e)),
    };
    
    let mut headers = HeaderMap::new();
    let auth_value = format!("token {}", token);
    
    match HeaderValue::from_str(&auth_value) {
        Ok(v) => headers.insert(AUTHORIZATION, v),
        Err(e) => return (false, format!("Invalid token format: {}", e)),
    };
    
    match HeaderValue::from_str("Sequential-Credential-Manager") {
        Ok(v) => headers.insert(USER_AGENT, v),
        Err(e) => return (false, format!("Failed to set user agent: {}", e)),
    };
    
    match client
        .get("https://api.github.com/user")
        .headers(headers)
        .send()
    {
        Ok(response) => {
            match response.status().as_u16() {
                200 => {
                    match response.json::<GitHubUser>() {
                        Ok(user) => (true, format!("Valid token for user: {}", user.login)),
                        Err(_) => (true, "Valid token".to_string()),
                    }
                }
                401 => (false, "Unauthorized (invalid token)".to_string()),
                403 => (false, "Forbidden (token lacks permissions or rate limited)".to_string()),
                404 => (false, "Not found".to_string()),
                status => (false, format!("Unexpected status: {}", status)),
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "Request timed out".to_string())
            } else if e.is_connect() {
                (false, "Connection failed".to_string())
            } else {
                (false, format!("Network error: {}", e))
            }
        }
    }
}

#[pyfunction]
#[pyo3(signature = (token, timeout=None))]
pub fn validate_openai_token(token: &str, timeout: Option<u64>) -> (bool, String) {
    let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
    
    let client = match create_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to create HTTP client: {}", e)),
    };
    
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bearer {}", token);
    
    match HeaderValue::from_str(&auth_value) {
        Ok(v) => headers.insert(AUTHORIZATION, v),
        Err(e) => return (false, format!("Invalid token format: {}", e)),
    };
    
    match client
        .get("https://api.openai.com/v1/models")
        .headers(headers)
        .send()
    {
        Ok(response) => {
            match response.status().as_u16() {
                200 => (true, "Valid OpenAI API key".to_string()),
                401 => (false, "Unauthorized (invalid API key)".to_string()),
                403 => (false, "Forbidden".to_string()),
                429 => (false, "Rate limited".to_string()),
                status => (false, format!("Unexpected status: {}", status)),
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "Request timed out".to_string())
            } else if e.is_connect() {
                (false, "Connection failed".to_string())
            } else {
                (false, format!("Network error: {}", e))
            }
        }
    }
}

#[pyfunction]
#[pyo3(signature = (token, timeout=None))]
pub fn validate_stripe_token(token: &str, timeout: Option<u64>) -> (bool, String) {
    let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
    
    let client = match create_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to create HTTP client: {}", e)),
    };
    
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bearer {}", token);
    
    match HeaderValue::from_str(&auth_value) {
        Ok(v) => headers.insert(AUTHORIZATION, v),
        Err(e) => return (false, format!("Invalid token format: {}", e)),
    };
    
    match client
        .get("https://api.stripe.com/v1/balance")
        .headers(headers)
        .send()
    {
        Ok(response) => {
            match response.status().as_u16() {
                200 => (true, "Valid Stripe API key".to_string()),
                401 => (false, "Unauthorized (invalid API key)".to_string()),
                403 => (false, "Forbidden".to_string()),
                status => (false, format!("Unexpected status: {}", status)),
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "Request timed out".to_string())
            } else if e.is_connect() {
                (false, "Connection failed".to_string())
            } else {
                (false, format!("Network error: {}", e))
            }
        }
    }
}

#[pyfunction]
#[pyo3(signature = (token, timeout=None))]
pub fn validate_slack_token(token: &str, timeout: Option<u64>) -> (bool, String) {
    let timeout_secs = timeout.unwrap_or(DEFAULT_TIMEOUT);
    
    let client = match create_client(timeout_secs) {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to create HTTP client: {}", e)),
    };
    
    let mut headers = HeaderMap::new();
    let auth_value = format!("Bearer {}", token);
    
    match HeaderValue::from_str(&auth_value) {
        Ok(v) => headers.insert(AUTHORIZATION, v),
        Err(e) => return (false, format!("Invalid token format: {}", e)),
    };
    
    match client
        .get("https://slack.com/api/auth.test")
        .headers(headers)
        .send()
    {
        Ok(response) => {
            match response.status().as_u16() {
                200 => {
                    if let Ok(json) = response.json::<serde_json::Value>() {
                        if json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                            let user = json.get("user").and_then(|v| v.as_str()).unwrap_or("unknown");
                            (true, format!("Valid Slack token for user: {}", user))
                        } else {
                            let error = json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
                            (false, format!("Invalid token: {}", error))
                        }
                    } else {
                        (false, "Failed to parse response".to_string())
                    }
                }
                401 => (false, "Unauthorized (invalid token)".to_string()),
                status => (false, format!("Unexpected status: {}", status)),
            }
        }
        Err(e) => {
            if e.is_timeout() {
                (false, "Request timed out".to_string())
            } else if e.is_connect() {
                (false, "Connection failed".to_string())
            } else {
                (false, format!("Network error: {}", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_invalid_discord_token() {
        let (valid, _msg) = validate_discord_token("invalid_token", Some(5));
        assert!(!valid);
    }
    
    #[test]
    fn test_invalid_github_token() {
        let (valid, _msg) = validate_github_token("invalid_token", Some(5));
        assert!(!valid);
    }
}
