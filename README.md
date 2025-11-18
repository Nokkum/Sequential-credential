<h1 align="center">Sequential's Credential Manager</h1>
<p align="center">
<img src="https://img.shields.io/badge/version-1.0-Blue" alt="Version 1.0">
<img src="https://img.shields.io/badge/Apache-2.0-Yellow" alt="Apache 2.0">
</p>
<p align="center">
  A modular, secure credential management system designed for developers. Stores tokens, API keys, and credentials encrypted, supports multiple storage backends, and includes utilities for migration, scanning, and RBAC enforcement.
</p>

# Features

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

# Directory Structure
```
project_root/
│
├─ main.py               # Entry point for GUI
├─ requirements.txt
├─ LICENSE
├─ README.md
├─ gui/
   ├─ 
│  ├─ app.py             # Main GUI logic
│  └─ tray.py            # Optional system tray scaffold
│
└─ core/
   ├─ __init__.py        
   ├─ security.py        # EncryptionManager
   ├─ database.py        # JSON + SQLite + optional Postgres storage
   ├─ configs.py         # Filesystem credential management
   ├─ migration.py       # Filesystem → DB migration
   ├─ launch.py          # (Optional bot launch removed if not needed)
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

# Installation
```bash
git clone <repo-url>
cd sequential-credential-manager
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

# Environment Variables
- **MASTER_PASSWORD**: Optional environment variable for the master password
```bash
# Linux/macOS
export MASTER_PASSWORD="your-strong-password"

# Windows PowerShell
$env:MASTER_PASSWORD="your-strong-password"
```

# Quick Start
```bash
python main.py
```

- Save, delete, import, or export credentials via GUI.
- Choose whether to store encrypted blobs in the database or filesystem.
- Use **Migrate** → **Filesystem** → **DB** to move legacy credentials into DB.

# CLI Utilities
- Migration Helper (file system → DB):
```bash
python -m core.migration --migrate
```

# Usage Examples
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

# Dependencies
- `cryptography` – encryption
- `psycopg2-binary` – optional Postgres support
- `tkinter` – GUI
- `pyperclip` – clipboard operations
- `requests` – token validation
- `jwt (PyJWT)` – JWT generation
- `PIL / pystray` – optional tray icon support

# Security Considerations
- Always use a strong master password.
- Clipboard auto-wipe reduces exposure but cannot guarantee OS-level protection.
- Role-based access is scaffold only; integrate with an authentication backend for multi-user setups.
