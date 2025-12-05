use pyo3::prelude::*;
use regex::Regex;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

struct SecretPattern {
    regex: Regex,
    label: &'static str,
}

static PATTERNS: LazyLock<Vec<SecretPattern>> = LazyLock::new(|| {
    vec![
        SecretPattern {
            regex: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            label: "Google API Key",
        },
        SecretPattern {
            regex: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(),
            label: "OpenAI Secret",
        },
        SecretPattern {
            regex: Regex::new(r"sk-proj-[A-Za-z0-9\-_]{80,}").unwrap(),
            label: "OpenAI Project Key",
        },
        SecretPattern {
            regex: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            label: "GitHub PAT",
        },
        SecretPattern {
            regex: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            label: "GitHub OAuth Token",
        },
        SecretPattern {
            regex: Regex::new(r"ghu_[A-Za-z0-9]{36}").unwrap(),
            label: "GitHub User Token",
        },
        SecretPattern {
            regex: Regex::new(r"ghs_[A-Za-z0-9]{36}").unwrap(),
            label: "GitHub Server Token",
        },
        SecretPattern {
            regex: Regex::new(r"ghr_[A-Za-z0-9]{36}").unwrap(),
            label: "GitHub Refresh Token",
        },
        SecretPattern {
            regex: Regex::new(r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}").unwrap(),
            label: "Discord Token",
        },
        SecretPattern {
            regex: Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
            label: "Slack Token",
        },
        SecretPattern {
            regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24}").unwrap(),
            label: "Stripe Live Secret Key",
        },
        SecretPattern {
            regex: Regex::new(r"sk_test_[0-9a-zA-Z]{24}").unwrap(),
            label: "Stripe Test Secret Key",
        },
        SecretPattern {
            regex: Regex::new(r"rk_live_[0-9a-zA-Z]{24}").unwrap(),
            label: "Stripe Restricted Key",
        },
        SecretPattern {
            regex: Regex::new(r"sq0atp-[0-9A-Za-z\-_]{22}").unwrap(),
            label: "Square Access Token",
        },
        SecretPattern {
            regex: Regex::new(r"sq0csp-[0-9A-Za-z\-_]{43}").unwrap(),
            label: "Square OAuth Secret",
        },
        SecretPattern {
            regex: Regex::new(r"AKIА[0-9A-Z]{16}").unwrap(),
            label: "AWS Access Key ID",
        },
        SecretPattern {
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            label: "AWS Access Key ID",
        },
        SecretPattern {
            regex: Regex::new(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            label: "Amazon MWS Auth Token",
        },
        SecretPattern {
            regex: Regex::new(r"EAACEdEose0cBA[0-9A-Za-z]+").unwrap(),
            label: "Facebook Access Token",
        },
        SecretPattern {
            regex: Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap(),
            label: "Google OAuth Client ID",
        },
        SecretPattern {
            regex: Regex::new(r"ya29\.[0-9A-Za-z_-]+").unwrap(),
            label: "Google OAuth Access Token",
        },
        SecretPattern {
            regex: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            label: "Mailgun API Key",
        },
        SecretPattern {
            regex: Regex::new(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}").unwrap(),
            label: "SendGrid API Key",
        },
        SecretPattern {
            regex: Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
            label: "Mailchimp API Key",
        },
        SecretPattern {
            regex: Regex::new(r"AC[a-zA-Z0-9_]{32}").unwrap(),
            label: "Twilio Account SID",
        },
        SecretPattern {
            regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            label: "Twilio API Key",
        },
        SecretPattern {
            regex: Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            label: "Private Key",
        },
        SecretPattern {
            regex: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            label: "PGP Private Key",
        },
    ]
});

#[pyfunction]
pub fn scan_text_for_secrets(text: &str) -> Vec<(String, String)> {
    let mut hits = Vec::new();
    
    for pattern in PATTERNS.iter() {
        for mat in pattern.regex.find_iter(text) {
            hits.push((pattern.label.to_string(), mat.as_str().to_string()));
        }
    }
    
    hits
}

#[pyfunction]
pub fn scan_files(paths: Vec<String>) -> Vec<(String, String, String)> {
    paths
        .par_iter()
        .filter_map(|path| {
            let path_obj = Path::new(path);
            
            if !path_obj.exists() || !path_obj.is_file() {
                return None;
            }
            
            if let Ok(metadata) = fs::metadata(path_obj) {
                if metadata.len() > 10 * 1024 * 1024 {
                    return None;
                }
            }
            
            match fs::read_to_string(path_obj) {
                Ok(content) => {
                    let hits = scan_text_for_secrets(&content);
                    if hits.is_empty() {
                        None
                    } else {
                        Some(
                            hits.into_iter()
                                .map(|(label, secret)| (path.clone(), label, secret))
                                .collect::<Vec<_>>()
                        )
                    }
                }
                Err(_) => None,
            }
        })
        .flatten()
        .collect()
}

pub fn scan_directory(dir: &str, recursive: bool) -> Vec<(String, String, String)> {
    let walker = if recursive {
        walkdir::WalkDir::new(dir)
    } else {
        walkdir::WalkDir::new(dir).max_depth(1)
    };
    
    let paths: Vec<String> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let path = e.path();
            let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            matches!(
                extension,
                "py" | "js" | "ts" | "jsx" | "tsx" | "json" | "yaml" | "yml" 
                | "env" | "sh" | "bash" | "zsh" | "config" | "cfg" | "ini"
                | "toml" | "xml" | "properties" | "rb" | "go" | "rs" | "java"
                | "kt" | "swift" | "php" | "cs" | "cpp" | "c" | "h" | "hpp"
            ) || path.file_name().map(|n| n.to_str().unwrap_or("").starts_with(".env")).unwrap_or(false)
        })
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();
    
    scan_files(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scan_google_api_key() {
        let text = "my key is AIzaSyC1234567890abcdefghijklmnopqrstuv";
        let hits = scan_text_for_secrets(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "Google API Key");
    }
    
    #[test]
    fn test_scan_github_pat() {
        let text = "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456";
        let hits = scan_text_for_secrets(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "GitHub PAT");
    }
    
    #[test]
    fn test_scan_no_secrets() {
        let text = "This is just normal text without any secrets.";
        let hits = scan_text_for_secrets(text);
        assert!(hits.is_empty());
    }
    
    #[test]
    fn test_scan_multiple_secrets() {
        let text = r#"
            GOOGLE_KEY=AIzaSyC1234567890abcdefghijklmnopqrstuv
            STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx
        "#;
        let hits = scan_text_for_secrets(text);
        assert!(hits.len() >= 2);
    }
}
