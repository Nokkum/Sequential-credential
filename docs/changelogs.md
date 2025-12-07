## Version 1.5 (2025-12-07)
- ### Rust Core Modules
  - **secure_memory** - Memory protection with automatic zeroization and mlock support
  - **scanner** - Fast secret scanning with regex patterns (Google API, OpenAI, GitHub, Discord tokens)
  - **security** - Encryption manager with Argon2id key derivation (upgraded from PBKDF2) and AES-256-GCM encryption
  - **crypto_advanced** - HKDF key derivation and AES key wrapping for per-provider keys
  - **database** - SQLite database operations with connection pooling
  - **validators** - API token validation for Discord, GitHub, OpenAI, Slack, and Stripe
- ### Python Wrapper Modules
  - `secure_memory.py` - Falls back to Python ctypes if Rust unavailable
  - `scanner.py` - Falls back to Python regex if Rust unavailable
  - `security.py` - Falls back to Python cryptography library if Rust unavailable
  - `crypto_advanced.py` - Falls back to Python HKDF if Rust unavailable
  - `validators.py` - Falls back to Python requests if Rust unavailable


## Version 1.2 (2025-12-01)
- ### Usability
  - Credential list view with a proper table showing provider, name, favorite status, and expiry
  - Real-time search/filter - just start typing to find credentials
  - Copy button with secure auto-wipe (clipboard clears after 30 seconds)
  - Keyboard shortcuts: Ctrl+S to save, Ctrl+C to copy, Ctrl+F to focus search, Escape to clear selection
- ### Security
 - Auto-lock timeout with configurable options (1, 5, 15, or 30 minutes of inactivity)
  - Password strength indicator when entering or rotating the master password
  - Lock screen requires master password to unlock
- ### Organization
  - Custom categories - create your own beyond tokens and APIs
  - Favorites toggle - mark important credentials for quick access (appear at top)
  - Notes field - add descriptions, reminders, or any information about credentials
  - Expiry dates - set when credentials expire
- ### Data Management
  - Expiry reminders - warning popup on startup for credentials expiring within 7 days
  - CSV import - import credentials from spreadsheets
  - Expiry status shown in the list (shows "EXPIRED", "3d left", etc.)
- ### Quality of Life
  - Dark mode toggle - switch between light and dark themes (flatly, darkly, superhero, solar, cyborg, vapor)
  - Theme preference persists between sessions
  - System tray support (when pystray is available) - minimize to tray with quick access menu


## Version 1.1 (2025-11-18)
- Added audit module
- Added backup module
- Added CLI module
- Clipboard auto-wipe functionality
- Profile switching
- RBAC enhancements


## Version 1.0 (2025-11-17)
- Initial release
- Tkinter GUI
- Encrypted credential storage
- Token validation (Discord, GitHub)
- Secret scanning
- Database migration helpers
