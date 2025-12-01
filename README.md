<h1 align="center">Sequential's Credential Manager</h1>
<p align="center">
<img src="https://img.shields.io/badge/version-1.0-Blue" alt="Version 1.2">
<img src="https://img.shields.io/badge/Apache-2.0-Yellow" alt="Apache 2.0">
</p>
<p align="center">
  A modular, secure credential management system designed for developers. Stores tokens, API keys, and credentials encrypted, supports multiple storage backends, and includes utilities for migration, scanning, and RBAC enforcement.
</p>

## Changes

### Version 1.2
- Credential list view with a proper table showing provider, name, favorite status, and expiry
- Real-time search/filter - just start typing to find credentials
- Copy button with secure auto-wipe (clipboard clears after 30 seconds)
- Keyboard shortcuts: Ctrl+S to save, Ctrl+C to copy, Ctrl+F to focus search, Escape to clear selection
- Auto-lock timeout with configurable options (1, 5, 15, or 30 minutes of inactivity)
- Password strength indicator when entering or rotating the master password
- Lock screen requires master password to unlock
- Custom categories - create your own beyond tokens and APIs
- Favorites toggle - mark important credentials for quick access (appear at top)
- Notes field - add descriptions, reminders, or any information about credentials
- Expiry dates - set when credentials expire
- Expiry reminders - warning popup on startup for credentials expiring within 7 days
- CSV import - import credentials from spreadsheets
- Expiry status shown in the list (shows "EXPIRED", "3d left", etc.)
- Dark mode toggle - switch between light and dark themes (flatly, darkly, superhero, solar, cyborg, vapor)
- Theme preference persists between sessions
- System tray support (when pystray is available) - minimize to tray with quick access menu


## Features

- **Master-Password Encryption**: All credentials are encrypted with a master password using modern cryptography (Fernet + PBKDF2).
- **Flexible Storage**: Store credentials in local JSON + filesystem encrypted blobs or SQLite database. Optional Postgres support.
- **Migration Utility**: Migrate existing filesystem-stored credentials into database blobs.
- **GUI Interface**: Tkinter-based GUI with master-password prompt, save/load/delete operations, import/export, and migration support.
- **Profile Management**: Manage multiple user profiles, each with independent credentials.
- **RBAC Support**: Role-based access control scaffold for admin, standard, and readonly roles.
- **Advanced Crypto**: Per-provider derived keys with AES key wrapping.
- **Token Validation**: Built-in token checks for Discord, GitHub, and more.
- **Clipboard Auto-Wipe**: Securely copy credentials to clipboard with automatic clearing.
- **Secret Scanner**: Scan text or files for sensitive information like API keys and tokens.
- **Extensible Templates**: Provider templates for standardized credential entry.
- **Audit Logging**: Tracks all actions performed within the credential manager, such as creating, updating, or deleting credentials and profiles. Logs are timestamped, encrypted, and can be filtered for easy review.
- **Backup & Restore**: Provides encrypted backup and restore functionality for credentials and configurations. Supports exporting/importing JSON + DB blobs, validating integrity, and securely merging backups with existing data.
- **Command-Line Interface**: Enables full headless access to the credential manager. Users can add, update, delete, list, export, import credentials, switch profiles, and perform filesystem-to-DB migration entirely from the terminal.

## Directory Structure
```
project_root/
│
├─ main.py               # Entry point for GUI
├─ requirements.txt
├─ LICENSE
├─ README.md
├─ docs/
│  └─ Changes.md         # Changelogs
│
├─ gui/
│  ├─ __init__.py
│  ├─ app.py             # Main GUI logic
│  └─ tray.py            # Optional system tray scaffold
│
└─ core/
   ├─ __init__.py        
   ├─ security.py        # EncryptionManager
   ├─ audit.py           # Auto logging
   ├─ backup.py          # Backup + restoration
   ├─ cli.py             # CLI Integration
   ├─ database.py        # JSON + SQLite + optional Postgres storage
   ├─ configs.py         # Filesystem credential management
   ├─ migration.py       # Filesystem → DB migration
   ├─ validators.py      # Token validation helpers
   ├─ expiry.py          # Token expiration heuristics
   ├─ profiles.py        # Profile management
   ├─ templates.py       # Provider templates
   ├─ roles.py           # RBAC scaffold
   ├─ generators.py      # JWT / GitHub app token helpers
   ├─ scanner.py         # Secret scanning
   ├─ crypto_advanced.py # Advanced cryptography utilities
   └─ secure_memory.py   # Secure memory handling
```

## Installation
```bash
git clone <repo-url>
cd sequential-credential-manager
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Environment Variables
- **MASTER_PASSWORD**: Optional environment variable for the master password
```bash
# Linux/macOS
export MASTER_PASSWORD="your-strong-password"

# Windows PowerShell
$env:MASTER_PASSWORD="your-strong-password"
```

## Quick Start
```bash
python main.py
```

- Save, delete, import, or export credentials via GUI.
- Choose whether to store encrypted blobs in the database or filesystem.
- Use **Migrate** → **Filesystem** → **DB** to move legacy credentials into DB.

## CLI Utilities
- Migration Helper (file system → DB):
```bash
python -m core.migration --migrate
```

## Usage Examples
- **Python imports via package interface**:
```python
from core import Database, EncryptionManager, ConfigManager, migrate_filesystem_to_db

db = Database()
enc = EncryptionManager("my_master_password")
cfg = ConfigManager(db, enc)
```
- **Secure clipboard copy**:
```python
from core.secure_memory import secure_copy

secure_copy("my-secret-token", timeout=10)
```

## Dependencies
- `cryptography` – encryption
- `psycopg2-binary` – optional Postgres support
- `tkinter` – GUI
- `pyperclip` – clipboard operations
- `requests` – token validation
- `jwt (PyJWT)` – JWT generation
- `PIL / pystray` – optional tray icon support

## Security Considerations
- Always use a strong master password.
- Clipboard auto-wipe reduces exposure but cannot guarantee OS-level protection.
- Role-based access is scaffold only; integrate with an authentication backend for multi-user setups.

## Versions
- **v1.2** – 2025-12-1
  - New table-based credential list with search/filter and favorites
  - Clipboard copy with 30s secure auto-wipe
  - Auto-lock timeout + lock screen requiring master password
  - Password strength indicator for master password setup/rotation
  - Custom categories, notes field, and expiry dates with reminders
  - CSV import and improved expiry status display
  - Dark mode + multiple themes with saved preferences
  - Keyboard shortcuts (Ctrl+S/C/F, Escape)
  - System tray support with quick-access menu

- **v1.1** – 2025-11-18
  - Added audit, backup, and CLI modules
  - Clipboard auto-wipe functionality
  - Profile switching and RBAC enhancements
- **v1.0** – 2025-11-17
  - Initial release with Tkinter GUI and encrypted credential storage
  - Added token validation and scanning
  - GUI refactor, database migration helpers
