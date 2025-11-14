"""
KMS Core functionality - Key Management System operations
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import secrets
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
import json

class KeyManagementSystem:
    """Key Management System for cryptographic key operations"""
    
    def __init__(self, config, storage_path):
        self.config = config
        self.storage_path = storage_path
        self.master_key = self._derive_master_key()
    
    def _derive_master_key(self):
        """Derive master key for key encryption"""
        # In production, this should use HSM or secure key storage
        salt = b'pki_kms_master_key_salt_v1'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.config['app']['secret_key'].encode())
    
    def generate_symmetric_key(self, algorithm='AES-256', purpose='encryption'):
        """Generate symmetric encryption key"""
        
        # Determine key size
        if algorithm == 'AES-128':
            key_size = 16
        elif algorithm == 'AES-192':
            key_size = 24
        elif algorithm == 'AES-256':
            key_size = 32
        elif algorithm == 'ChaCha20':
            key_size = 32
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Generate random key
        key_material = secrets.token_bytes(key_size)
        
        # Encrypt key material with master key
        encrypted_key = self._encrypt_key_material(key_material)
        
        return {
            'key_material': encrypted_key,
            'algorithm': algorithm,
            'key_size': key_size * 8,  # bits
            'purpose': purpose,
            'type': 'symmetric'
        }
    
    def generate_asymmetric_key(self, algorithm='RSA-2048', purpose='signing'):
        """Generate asymmetric key pair"""
        
        if algorithm.startswith('RSA'):
            key_size = int(algorithm.split('-')[1])
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif algorithm.startswith('ECC'):
            curve_name = algorithm.split('-')[1]
            if curve_name == 'P256':
                curve = ec.SECP256R1()
            elif curve_name == 'P384':
                curve = ec.SECP384R1()
            elif curve_name == 'P521':
                curve = ec.SECP521R1()
            else:
                raise ValueError(f"Unsupported curve: {curve_name}")
            private_key = ec.generate_private_key(curve, default_backend())
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Encrypt private key material with master key
        encrypted_private = self._encrypt_key_material(private_pem)
        
        return {
            'private_key_material': encrypted_private,
            'public_key_material': public_pem,
            'algorithm': algorithm,
            'key_size': key_size if algorithm.startswith('RSA') else None,
            'purpose': purpose,
            'type': 'asymmetric'
        }
    
    def _encrypt_key_material(self, key_material):
        """Encrypt key material with master key"""
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(key_material) + encryptor.finalize()
        
        # Return IV + tag + ciphertext
        return iv + encryptor.tag + ciphertext
    
    def _decrypt_key_material(self, encrypted_data):
        """Decrypt key material with master key"""
        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def encrypt_data(self, key_id, data, encrypted_key_material):
        """Encrypt data using a managed key"""
        # Decrypt the key material
        key_material = self._decrypt_key_material(encrypted_key_material)
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_material),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        if isinstance(data, str):
            data = data.encode('utf-8')
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return encrypted data with metadata
        return {
            'key_id': key_id,
            'iv': b64encode(iv).decode('utf-8'),
            'tag': b64encode(encryptor.tag).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt_data(self, encrypted_data, encrypted_key_material):
        """Decrypt data using a managed key"""
        # Decrypt the key material
        key_material = self._decrypt_key_material(encrypted_key_material)
        
        # Extract components
        iv = b64decode(encrypted_data['iv'])
        tag = b64decode(encrypted_data['tag'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key_material),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def rotate_key(self, old_key_data, new_algorithm=None):
        """Rotate a key to a new version"""
        # Generate new key with same or specified algorithm
        algorithm = new_algorithm or old_key_data['algorithm']
        
        if old_key_data['type'] == 'symmetric':
            return self.generate_symmetric_key(algorithm, old_key_data['purpose'])
        else:
            return self.generate_asymmetric_key(algorithm, old_key_data['purpose'])
    
    def export_key(self, encrypted_key_material, key_type, password=None):
        """Export key in encrypted format"""
        # Decrypt key material
        key_material = self._decrypt_key_material(encrypted_key_material)
        
        if password:
            # Re-encrypt with password
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            export_key = kdf.derive(password.encode())
            
            iv = secrets.token_bytes(16)
            cipher = Cipher(
                algorithms.AES(export_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(key_material) + encryptor.finalize()
            
            return {
                'encrypted': True,
                'salt': b64encode(salt).decode('utf-8'),
                'iv': b64encode(iv).decode('utf-8'),
                'tag': b64encode(encryptor.tag).decode('utf-8'),
                'data': b64encode(ciphertext).decode('utf-8')
            }
        else:
            # Export in plain (not recommended)
            return {
                'encrypted': False,
                'data': b64encode(key_material).decode('utf-8')
            }
    
    def import_key(self, key_data, password=None):
        """Import key from external source"""
        if key_data.get('encrypted'):
            # Decrypt with password
            salt = b64decode(key_data['salt'])
            iv = b64decode(key_data['iv'])
            tag = b64decode(key_data['tag'])
            ciphertext = b64decode(key_data['data'])
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            import_key = kdf.derive(password.encode())
            
            cipher = Cipher(
                algorithms.AES(import_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            key_material = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            key_material = b64decode(key_data['data'])
        
        # Encrypt with master key
        encrypted_key = self._encrypt_key_material(key_material)
        
        return encrypted_key
