#  Personal Security Toolkit            

A Python based data protection, encryption, and system integrity monitoring.

## Features

### Core Security Modules
- **Secure Password Generation**
  - Cryptographically strong random passwords
  - Customizable length and character sets
- **Encryption Key Management**
  - Master-key encrypted key storage
  - Automatic key rotation (30-day default)
  - Duplicate key collision handling
- **File Integrity Monitoring**
  - SHA-256 checksum verification
  - Automated change detection
- **Threat Detection**
  - Phishing URL identification
  - Suspicious file pattern recognition

### Advanced Security
- PBKDF2 key derivation
- Secure file deletion
- Automatic backup system
- Config corruption recovery

## 🛠️ Installation

### Requirements
- Python 3.8+
- Linux/macOS (Windows support limited)
- `cryptography` package

```bash
pip install cryptography


--------------------------------------------------------------------------

from toolkit import SecurityToolkit

# Initialize toolkit
toolkit = SecurityToolkit()

# Generate a secure password
password = secrets.token_urlsafe(16)

# Create encryption key
toolkit.key_manager.generate_key("personal_files")

# Verify file integrity
status, reason = toolkit.file_monitor.verify_file(Path("important.doc"))



-------------------------------------------------------------------------


# Run interactive demo
python Personal_Security_Toolkit.py

# Generate password only
python -c "import secrets; print(secrets.token_urlsafe(16))"

# Encrypt a file
python -c "from toolkit import SecurityToolkit; t=SecurityToolkit(); t.encrypt_file('private.txt', 'mykey')"
