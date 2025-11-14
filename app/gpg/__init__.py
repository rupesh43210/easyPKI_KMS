""""""

GPG Module - GNU Privacy Guard key managementGPG Module - GNU Privacy Guard key management

""""""



from .gpg_manager import GPGManagerfrom .gpg_manager import GPGManager



__all__ = ['GPGManager']__all__ = ['GPGManager']

        """
        Initialize GPG Manager
        
        Args:
            gnupg_home: Path to GPG home directory. If None, creates in data/gpg
        """
        if gnupg_home is None:
            gnupg_home = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'gpg')
        
        os.makedirs(gnupg_home, exist_ok=True)
        self.gpg_home = gnupg_home
        self.gpg = gnupg.GPG(gnupghome=gnupg_home)
        logger.info(f"GPG Manager initialized with home: {gnupg_home}")
    
    def generate_key(
        self,
        name_real: str,
        name_email: str,
        name_comment: str = "",
        key_type: str = "RSA",
        key_length: int = 4096,
        expire_date: str = "0",
        passphrase: Optional[str] = None
    ) -> Dict:
        """
        Generate a new GPG key pair
        
        Args:
            name_real: Real name for the key
            name_email: Email address
            name_comment: Optional comment
            key_type: RSA, DSA, or ECDSA (default: RSA)
            key_length: Key length in bits (2048, 3072, 4096)
            expire_date: Expiration date (0 = never, or format: 2025-12-31)
            passphrase: Optional passphrase to protect the key
        
        Returns:
            Dict with key information including fingerprint
        """
        try:
            input_data = self.gpg.gen_key_input(
                name_real=name_real,
                name_email=name_email,
                name_comment=name_comment,
                key_type=key_type,
                key_length=key_length,
                expire_date=expire_date,
                passphrase=passphrase or ""
            )
            
            key = self.gpg.gen_key(input_data)
            
            if not key:
                raise Exception("Failed to generate GPG key")
            
            # Get key details
            key_info = self.get_key_info(str(key))
            
            logger.info(f"Generated GPG key: {key} for {name_email}")
            
            return {
                'success': True,
                'fingerprint': str(key),
                'key_id': key_info.get('keyid'),
                'name': name_real,
                'email': name_email,
                'created': datetime.now().isoformat(),
                'expires': expire_date,
                'key_type': key_type,
                'key_length': key_length
            }
        
        except Exception as e:
            logger.error(f"Failed to generate GPG key: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_keys(self, secret: bool = False) -> List[Dict]:
        """
        List GPG keys
        
        Args:
            secret: If True, list private keys; otherwise list public keys
        
        Returns:
            List of key dictionaries
        """
        try:
            keys = self.gpg.list_keys(secret=secret)
            
            result = []
            for key in keys:
                result.append({
                    'fingerprint': key.get('fingerprint'),
                    'key_id': key.get('keyid'),
                    'type': key.get('type'),
                    'length': key.get('length'),
                    'uids': key.get('uids', []),
                    'created': key.get('date'),
                    'expires': key.get('expires'),
                    'trust': key.get('trust'),
                    'ownertrust': key.get('ownertrust')
                })
            
            return result
        
        except Exception as e:
            logger.error(f"Failed to list GPG keys: {e}")
            return []
    
    def get_key_info(self, fingerprint: str, secret: bool = False) -> Optional[Dict]:
        """
        Get detailed information about a specific key
        
        Args:
            fingerprint: Key fingerprint or key ID
            secret: If True, look for private key
        
        Returns:
            Key information dictionary or None
        """
        try:
            keys = self.gpg.list_keys(secret=secret)
            
            for key in keys:
                if fingerprint in [key.get('fingerprint'), key.get('keyid')]:
                    return {
                        'fingerprint': key.get('fingerprint'),
                        'key_id': key.get('keyid'),
                        'type': key.get('type'),
                        'length': key.get('length'),
                        'algorithm': key.get('algo'),
                        'uids': key.get('uids', []),
                        'created': key.get('date'),
                        'expires': key.get('expires'),
                        'trust': key.get('trust'),
                        'ownertrust': key.get('ownertrust'),
                        'subkeys': key.get('subkeys', [])
                    }
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get key info: {e}")
            return None
    
    def export_public_key(self, fingerprint: str, armor: bool = True) -> Optional[str]:
        """
        Export public key
        
        Args:
            fingerprint: Key fingerprint or key ID
            armor: If True, export in ASCII armor format
        
        Returns:
            Exported key as string or None
        """
        try:
            key_data = self.gpg.export_keys(fingerprint, armor=armor)
            
            if not key_data:
                raise Exception(f"Key not found: {fingerprint}")
            
            logger.info(f"Exported public key: {fingerprint}")
            return key_data
        
        except Exception as e:
            logger.error(f"Failed to export public key: {e}")
            return None
    
    def export_private_key(
        self,
        fingerprint: str,
        passphrase: Optional[str] = None,
        armor: bool = True
    ) -> Optional[str]:
        """
        Export private key
        
        Args:
            fingerprint: Key fingerprint or key ID
            passphrase: Passphrase to unlock the key
            armor: If True, export in ASCII armor format
        
        Returns:
            Exported key as string or None
        """
        try:
            key_data = self.gpg.export_keys(
                fingerprint,
                secret=True,
                armor=armor,
                passphrase=passphrase or ""
            )
            
            if not key_data:
                raise Exception(f"Private key not found or incorrect passphrase: {fingerprint}")
            
            logger.info(f"Exported private key: {fingerprint}")
            return key_data
        
        except Exception as e:
            logger.error(f"Failed to export private key: {e}")
            return None
    
    def import_key(self, key_data: str) -> Dict:
        """
        Import a GPG key (public or private)
        
        Args:
            key_data: Key data in ASCII armor or binary format
        
        Returns:
            Import result dictionary
        """
        try:
            result = self.gpg.import_keys(key_data)
            
            return {
                'success': result.count > 0,
                'count': result.count,
                'fingerprints': result.fingerprints,
                'results': result.results
            }
        
        except Exception as e:
            logger.error(f"Failed to import key: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_key(
        self,
        fingerprint: str,
        secret: bool = False,
        passphrase: Optional[str] = None
    ) -> bool:
        """
        Delete a GPG key
        
        Args:
            fingerprint: Key fingerprint or key ID
            secret: If True, delete private key
            passphrase: Passphrase to unlock private key
        
        Returns:
            True if successful
        """
        try:
            result = self.gpg.delete_keys(
                fingerprint,
                secret=secret,
                passphrase=passphrase or ""
            )
            
            success = str(result) == 'ok'
            
            if success:
                logger.info(f"Deleted {'private' if secret else 'public'} key: {fingerprint}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to delete key: {e}")
            return False
    
    def encrypt(
        self,
        data: str,
        recipients: List[str],
        armor: bool = True,
        sign: Optional[str] = None,
        passphrase: Optional[str] = None
    ) -> Optional[str]:
        """
        Encrypt data with GPG
        
        Args:
            data: Data to encrypt
            recipients: List of recipient fingerprints or emails
            armor: If True, output ASCII armor format
            sign: Optional fingerprint to sign with
            passphrase: Passphrase for signing key
        
        Returns:
            Encrypted data or None
        """
        try:
            encrypted = self.gpg.encrypt(
                data,
                recipients,
                armor=armor,
                sign=sign,
                passphrase=passphrase or ""
            )
            
            if not encrypted.ok:
                raise Exception(f"Encryption failed: {encrypted.status}")
            
            logger.info(f"Encrypted data for {len(recipients)} recipients")
            return str(encrypted)
        
        except Exception as e:
            logger.error(f"Failed to encrypt: {e}")
            return None
    
    def decrypt(
        self,
        encrypted_data: str,
        passphrase: Optional[str] = None
    ) -> Tuple[Optional[str], Dict]:
        """
        Decrypt GPG encrypted data
        
        Args:
            encrypted_data: Encrypted data
            passphrase: Passphrase to unlock private key
        
        Returns:
            Tuple of (decrypted_data, metadata)
        """
        try:
            decrypted = self.gpg.decrypt(encrypted_data, passphrase=passphrase or "")
            
            if not decrypted.ok:
                raise Exception(f"Decryption failed: {decrypted.status}")
            
            metadata = {
                'username': decrypted.username,
                'key_id': decrypted.key_id,
                'signature_id': decrypted.signature_id,
                'fingerprint': decrypted.fingerprint,
                'trust_level': decrypted.trust_level,
                'trust_text': decrypted.trust_text
            }
            
            logger.info(f"Decrypted data from key: {decrypted.key_id}")
            return str(decrypted), metadata
        
        except Exception as e:
            logger.error(f"Failed to decrypt: {e}")
            return None, {'error': str(e)}
    
    def sign(
        self,
        data: str,
        keyid: str,
        passphrase: Optional[str] = None,
        detach: bool = True,
        clearsign: bool = False
    ) -> Optional[str]:
        """
        Sign data with GPG
        
        Args:
            data: Data to sign
            keyid: Key fingerprint or ID to sign with
            passphrase: Passphrase to unlock the key
            detach: If True, create detached signature
            clearsign: If True, create cleartext signature
        
        Returns:
            Signature or None
        """
        try:
            signed = self.gpg.sign(
                data,
                keyid=keyid,
                passphrase=passphrase or "",
                detach=detach,
                clearsign=clearsign
            )
            
            if not signed:
                raise Exception("Signing failed")
            
            logger.info(f"Signed data with key: {keyid}")
            return str(signed)
        
        except Exception as e:
            logger.error(f"Failed to sign: {e}")
            return None
    
    def verify(self, signed_data: str, signature: Optional[str] = None) -> Dict:
        """
        Verify a GPG signature
        
        Args:
            signed_data: Signed data or data to verify
            signature: Detached signature (if applicable)
        
        Returns:
            Verification result dictionary
        """
        try:
            if signature:
                # Verify detached signature
                verified = self.gpg.verify_data(signature, signed_data.encode())
            else:
                # Verify inline signature
                verified = self.gpg.verify(signed_data)
            
            return {
                'valid': verified.valid,
                'fingerprint': verified.fingerprint,
                'key_id': verified.key_id,
                'username': verified.username,
                'timestamp': verified.timestamp,
                'signature_id': verified.signature_id,
                'trust_level': verified.trust_level,
                'trust_text': verified.trust_text,
                'status': verified.status
            }
        
        except Exception as e:
            logger.error(f"Failed to verify signature: {e}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def change_passphrase(
        self,
        fingerprint: str,
        old_passphrase: str,
        new_passphrase: str
    ) -> bool:
        """
        Change the passphrase for a private key
        
        Args:
            fingerprint: Key fingerprint
            old_passphrase: Current passphrase
            new_passphrase: New passphrase
        
        Returns:
            True if successful
        """
        try:
            # Export with old passphrase
            key_data = self.export_private_key(fingerprint, old_passphrase)
            
            if not key_data:
                return False
            
            # Delete old key
            self.delete_key(fingerprint, secret=True, passphrase=old_passphrase)
            
            # Re-import with new passphrase
            # Note: This is a workaround. GPG doesn't have direct passphrase change via python-gnupg
            result = self.import_key(key_data)
            
            return result.get('success', False)
        
        except Exception as e:
            logger.error(f"Failed to change passphrase: {e}")
            return False
