import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import string
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# -------------------------------------
# Configuration & Constants
# -------------------------------------
class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)

DEFAULT_CONFIG = {
    'base_dir': str(Path.home() / ".security_toolkit"),
    'backup_dir': str(Path.home() / ".security_toolkit/backups"),
    'log_level': logging.INFO,
    'key_rotation_days': 30,
    'backup_interval_hours': 24,
    'secure_delete_passes': 3,
    'whitelisted_ips': ["127.0.0.1"],
    'whitelisted_domains': ["example.com", "trusted.org"],
    'suspicious_keywords': ['login', 'verify', 'update', 'secure', 'account', 'bank', 'confirm'],
    'suspicious_patterns': [
        r"@.*@", r"//.*//", r"[^a-zA-Z0-9\-\.]", 
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r"\.(exe|bat|cmd|js)$"
    ]
}

# -------------------------------------
# Security Configuration Manager
# -------------------------------------
class SecurityConfig:
    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        self.config_path = Path(config_path) if config_path else Path(DEFAULT_CONFIG['base_dir']) / "config.json"
        self.base_dir = Path(DEFAULT_CONFIG['base_dir'])
        self.backup_dir = Path(DEFAULT_CONFIG['backup_dir'])
        
        # Ensure directories exist
        self.base_dir.mkdir(exist_ok=True, mode=0o700)
        self.backup_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Initialize logging first
        logging.basicConfig(
            filename=self.base_dir / "toolkit.log",
            level=DEFAULT_CONFIG['log_level'],
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Load or create config with corruption handling
        self._config = self._safe_load_config()
        
        # Convert paths back to Path objects after loading
        self._config['base_dir'] = Path(self._config['base_dir'])
        self._config['backup_dir'] = Path(self._config['backup_dir'])
    
    def _safe_load_config(self) -> Dict:
        """Load config with corruption handling"""
        if not self.config_path.exists():
            return DEFAULT_CONFIG.copy()
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Validate basic config structure
            if not isinstance(config, dict):
                raise ValueError("Config is not a dictionary")
                
            # Merge with defaults
            merged = {**DEFAULT_CONFIG, **config}
            
            # Backup if file was corrupted but is now valid
            if os.path.exists(str(self.config_path) + ".bak"):
                backup_path = Path(str(self.config_path) + ".bak")
                backup_path.unlink()
                
            return merged
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"Config file corrupted, recreating: {e}")
            backup_path = Path(str(self.config_path) + ".bak")
            try:
                self.config_path.rename(backup_path)
            except Exception as rename_error:
                logging.error(f"Failed to backup corrupted config: {rename_error}")
            return DEFAULT_CONFIG.copy()
    
    def _save_config(self):
        """Save config with error handling"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, cls=EnhancedJSONEncoder, indent=2)
            os.chmod(self.config_path, 0o600)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
    
    def __getitem__(self, key):
        return self._config[key]
    
    def __setitem__(self, key, value):
        self._config[key] = value
        self._save_config()

# -------------------------------------
# Cryptographic Utilities
# -------------------------------------
class CryptoUtils:
    @staticmethod
    def generate_fernet_key(password: Optional[str] = None, salt: Optional[bytes] = None) -> bytes:
        """Generate a Fernet key, optionally from a password"""
        if password is None:
            return Fernet.generate_key()
        
        salt = salt or secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def secure_delete(path: Path, passes: int = DEFAULT_CONFIG['secure_delete_passes']):
        """Securely delete a file by overwriting it"""
        try:
            with open(path, 'ba+') as f:
                length = f.tell()
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(length))
                    f.flush()
                    os.fsync(f.fileno())
            path.unlink()
        except Exception as e:
            logging.error(f"Secure delete failed for {path}: {e}")
            raise

# -------------------------------------
# Key Management System
# -------------------------------------
class KeyManager:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.master_key_path = config.base_dir / "master.key"
        self.keys_file = config.base_dir / "keys.json.enc"
        self.key_backups = config.backup_dir / "key_backups"
        self.key_backups.mkdir(exist_ok=True, mode=0o700)
        
        self.master_key = self._initialize_master_key()
        self.keys = self._safe_load_keys()
        self.last_backup = 0
    
    def _initialize_master_key(self) -> Fernet:
        """Load or create the master encryption key"""
        if not self.master_key_path.exists():
            key = CryptoUtils.generate_fernet_key()
            self.master_key_path.write_bytes(key)
            os.chmod(self.master_key_path, 0o600)
            logging.info("Generated new master key")
            return Fernet(key)
        
        try:
            key = self.master_key_path.read_bytes()
            return Fernet(key)
        except Exception as e:
            logging.error(f"Failed to load master key: {e}")
            # Create new key if existing one is invalid
            key = CryptoUtils.generate_fernet_key()
            self.master_key_path.write_bytes(key)
            os.chmod(self.master_key_path, 0o600)
            logging.info("Generated new master key due to corruption")
            return Fernet(key)
    
    def _safe_load_keys(self) -> Dict[str, str]:
        """Load keys with corruption handling"""
        if not self.keys_file.exists():
            return {}
        
        try:
            encrypted = self.keys_file.read_bytes()
            decrypted = self.master_key.decrypt(encrypted).decode()
            keys = json.loads(decrypted)
            
            if not isinstance(keys, dict):
                raise ValueError("Keys data is not a dictionary")
                
            return keys
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"Keys file corrupted, recreating: {e}")
            backup_path = self.key_backups / f"keys_corrupted_{int(time.time())}.json.enc"
            try:
                self.keys_file.rename(backup_path)
            except Exception as rename_error:
                logging.error(f"Failed to backup corrupted keys: {rename_error}")
            return {}
        except Exception as e:
            logging.error(f"Failed to load keys: {e}")
            return {}
    
    def _save_keys(self):
        """Save keys with error handling"""
        try:
            data = json.dumps(self.keys).encode()
            encrypted = self.master_key.encrypt(data)
            self.keys_file.write_bytes(encrypted)
            os.chmod(self.keys_file, 0o600)
        except Exception as e:
            logging.error(f"Failed to save keys: {e}")
            raise
    
    def _backup_keys(self):
        """Create timestamped backup of keys"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.key_backups / f"keys_{timestamp}.json.enc"
        try:
            backup_file.write_bytes(self.keys_file.read_bytes())
            os.chmod(backup_file, 0o600)
            self.last_backup = time.time()
            logging.info(f"Created key backup: {backup_file}")
        except Exception as e:
            logging.error(f"Failed to create key backup: {e}")
    
    def generate_key(self, name: str, password: Optional[str] = None) -> str:
        """Generate and store a new named key"""
        if name in self.keys:
            # Generate a unique name instead of failing
            new_name = f"{name}_{secrets.token_hex(2)}"
            logging.warning(f"Key '{name}' exists, using '{new_name}' instead")
            return self.generate_key(new_name, password)
        
        try:
            key = CryptoUtils.generate_fernet_key(password).decode()
            self.keys[name] = key
            self._save_keys()
            
            # Create backup if enough time has passed
            if time.time() - self.last_backup > self.config['backup_interval_hours'] * 3600:
                self._backup_keys()
            
            logging.info(f"Generated new key: {name}")
            return key
        except Exception as e:
            logging.error(f"Failed to generate key: {e}")
            raise
    
    def get_key(self, name: str) -> Optional[str]:
        """Retrieve a named key"""
        return self.keys.get(name)

# -------------------------------------
# Main Security Toolkit Class
# -------------------------------------
class SecurityToolkit:
    def __init__(self):
        self.config = SecurityConfig()
        self.key_manager = KeyManager(self.config)
        
    def demo(self):
        """Demonstrate toolkit functionality"""
        print("\n=== Security Toolkit v3.0 ===")
        
        # Password generation demo
        print("\n[Password Generation]")
        password = secrets.token_urlsafe(16)
        print(f"Generated Password: {password}")
        
        # Key management demo
        print("\n[Key Management]")
        key_name = "demo_key"
        try:
            generated_key = self.key_manager.generate_key(key_name)
            print(f"Generated key: {key_name}")
            retrieved_key = self.key_manager.get_key(key_name)
            print(f"Key retrieved: {bool(retrieved_key)}")
            
            # Test duplicate key handling
            print("\n[Duplicate Key Test]")
            try:
                duplicate_key = self.key_manager.generate_key(key_name)
                print(f"Duplicate key handled gracefully: {duplicate_key}")
            except Exception as e:
                print(f"Duplicate key failed: {e}")
        except Exception as e:
            print(f"Key generation failed: {e}")

# -------------------------------------
# Entry Point
# -------------------------------------
if __name__ == "__main__":
    toolkit = SecurityToolkit()
    toolkit.demo()
