"""
PKI Core functionality - Certificate Authority operations
"""
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import os
import secrets
from pathlib import Path

class CertificateAuthority:
    """Certificate Authority for PKI operations"""
    
    def __init__(self, config, storage_path):
        self.config = config
        self.storage_path = Path(storage_path)
        self.ca_path = Path(config['storage']['ca_path'])
        self.certs_path = Path(config['storage']['certs_path'])
        
    def initialize_ca(self):
        """Initialize Root and Intermediate CA"""
        # Create Root CA if not exists
        root_ca_cert_path = self.ca_path / 'root_ca.crt'
        root_ca_key_path = self.ca_path / 'root_ca.key'
        
        if not root_ca_cert_path.exists():
            print("📜 Creating Root CA...")
            root_key, root_cert = self._create_root_ca()
            self._save_certificate_and_key(root_cert, root_key, 
                                          root_ca_cert_path, root_ca_key_path)
            print(f"✅ Root CA created: {root_ca_cert_path}")
        else:
            print(f"✅ Root CA already exists: {root_ca_cert_path}")
            root_key, root_cert = self._load_certificate_and_key(
                root_ca_cert_path, root_ca_key_path)
        
        # Create Intermediate CA if not exists
        int_ca_cert_path = self.ca_path / 'intermediate_ca.crt'
        int_ca_key_path = self.ca_path / 'intermediate_ca.key'
        
        if not int_ca_cert_path.exists():
            print("📜 Creating Intermediate CA...")
            int_key, int_cert = self._create_intermediate_ca(root_key, root_cert)
            self._save_certificate_and_key(int_cert, int_key,
                                          int_ca_cert_path, int_ca_key_path)
            print(f"✅ Intermediate CA created: {int_ca_cert_path}")
        else:
            print(f"✅ Intermediate CA already exists: {int_ca_cert_path}")
        
        return True
    
    def _create_root_ca(self):
        """Create Root CA certificate"""
        config = self.config['pki']['root_ca']
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config['key_size'],
            backend=default_backend()
        )
        
        # Create subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, config['country']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config['state']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, config['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config['organizational_unit']),
            x509.NameAttribute(NameOID.COMMON_NAME, config['common_name']),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, config['email']),
        ])
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=config['validity_days'])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, getattr(hashes, config['hash_algorithm'])(), default_backend())
        
        return private_key, cert
    
    def _create_intermediate_ca(self, root_key, root_cert):
        """Create Intermediate CA certificate"""
        config = self.config['pki']['intermediate_ca']
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config['key_size'],
            backend=default_backend()
        )
        
        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, config['country']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config['state']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, config['locality']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config['organization']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config['organizational_unit']),
            x509.NameAttribute(NameOID.COMMON_NAME, config['common_name']),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, config['email']),
        ])
        
        # Create certificate signed by Root CA
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=config['validity_days'])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False,
        ).sign(root_key, getattr(hashes, config['hash_algorithm'])(), default_backend())
        
        return private_key, cert
    
    def create_certificate(self, common_name, cert_type='server', 
                          validity_days=None, key_size=None,
                          san_list=None, organization=None):
        """Create and sign a certificate"""
        
        if validity_days is None:
            validity_days = self.config['pki']['certificates']['default_validity_days']
        if key_size is None:
            key_size = self.config['pki']['certificates']['default_key_size']
        
        # Load Intermediate CA
        int_ca_cert_path = self.ca_path / 'intermediate_ca.crt'
        int_ca_key_path = self.ca_path / 'intermediate_ca.key'
        issuer_key, issuer_cert = self._load_certificate_and_key(
            int_ca_cert_path, int_ca_key_path)
        
        # Generate private key for certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Build subject
        subject_attrs = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        if organization:
            subject_attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        
        subject = x509.Name(subject_attrs)
        
        # Create certificate builder
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        
        # Add key usage based on certificate type
        if cert_type == 'server':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            # Add SAN
            if san_list:
                san = [x509.DNSName(name) for name in san_list]
            else:
                san = [x509.DNSName(common_name)]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san),
                critical=False,
            )
            
        elif cert_type == 'client':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            
        elif cert_type == 'email':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]),
                critical=False,
            )
            
        elif cert_type == 'code_signing':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                ]),
                critical=False,
            )
        
        # Sign certificate
        cert = builder.sign(
            issuer_key, 
            getattr(hashes, self.config['pki']['certificates']['default_hash_algorithm'])(),
            default_backend()
        )
        
        return private_key, cert
    
    def _save_certificate_and_key(self, cert, key, cert_path, key_path):
        """Save certificate and private key to files"""
        # Save certificate
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key (encrypted)
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    self.config['app']['secret_key'].encode()
                )
            ))
    
    def _load_certificate_and_key(self, cert_path, key_path):
        """Load certificate and private key from files"""
        # Load certificate
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Load private key
        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=self.config['app']['secret_key'].encode(),
                backend=default_backend()
            )
        
        return key, cert
    
    def export_certificate_bundle(self, cert_serial):
        """Export certificate with full chain"""
        # This would load the certificate and create a bundle with intermediate and root
        pass
    
    def sign_csr(self, csr_pem, cert_type='server', validity_days=None, san_list=None):
        """Sign a Certificate Signing Request (CSR)"""
        
        if validity_days is None:
            validity_days = self.config['pki']['certificates']['default_validity_days']
        
        # Load the CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode() if isinstance(csr_pem, str) else csr_pem, 
                                      default_backend())
        
        # Verify CSR signature
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        
        # Load Intermediate CA
        int_ca_cert_path = self.ca_path / 'intermediate_ca.crt'
        int_ca_key_path = self.ca_path / 'intermediate_ca.key'
        issuer_key, issuer_cert = self._load_certificate_and_key(
            int_ca_cert_path, int_ca_key_path)
        
        # Create certificate builder using CSR information
        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            issuer_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        
        # Add key usage based on certificate type
        if cert_type == 'server':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            # Add SAN
            if san_list:
                san = [x509.DNSName(name) for name in san_list]
            else:
                # Try to get CN from subject
                cn = None
                for attr in csr.subject:
                    if attr.oid == NameOID.COMMON_NAME:
                        cn = attr.value
                        break
                san = [x509.DNSName(cn)] if cn else []
            
            if san:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san),
                    critical=False,
                )
            
        elif cert_type == 'client':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            
        elif cert_type == 'email':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ]),
                critical=False,
            )
            
        elif cert_type == 'code_signing':
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                ]),
                critical=False,
            )
        
        # Copy any requested extensions from CSR (if safe)
        for ext in csr.extensions:
            # Skip extensions we're already adding
            if ext.oid in [ExtensionOID.BASIC_CONSTRAINTS, 
                          ExtensionOID.KEY_USAGE,
                          ExtensionOID.EXTENDED_KEY_USAGE,
                          ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                          ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                          ExtensionOID.SUBJECT_ALTERNATIVE_NAME]:
                continue
            # Add other safe extensions from CSR
            builder = builder.add_extension(ext.value, critical=ext.critical)
        
        # Sign certificate
        cert = builder.sign(
            issuer_key, 
            getattr(hashes, self.config['pki']['certificates']['default_hash_algorithm'])(),
            default_backend()
        )
        
        return cert
    
    def generate_crl(self, revoked_certificates):
        """Generate Certificate Revocation List"""
        int_ca_cert_path = self.ca_path / 'intermediate_ca.crt'
        int_ca_key_path = self.ca_path / 'intermediate_ca.key'
        issuer_key, issuer_cert = self._load_certificate_and_key(
            int_ca_cert_path, int_ca_key_path)
        
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(
            datetime.utcnow() + timedelta(days=self.config['pki']['crl']['validity_days'])
        )
        
        # Add revoked certificates
        for cert_info in revoked_certificates:
            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                int(cert_info['serial_number'], 16)
            ).revocation_date(
                cert_info['revoked_at']
            ).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)
        
        # Sign CRL
        crl = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        
        return crl
    
    def verify_certificate_chain(self, cert_pem):
        """Verify certificate chain of trust"""
        try:
            # Load the certificate
            if isinstance(cert_pem, str):
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            else:
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Load CA certificates
            root_ca_cert_path = self.ca_path / 'root_ca.crt'
            int_ca_cert_path = self.ca_path / 'intermediate_ca.crt'
            
            with open(root_ca_cert_path, 'rb') as f:
                root_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            with open(int_ca_cert_path, 'rb') as f:
                int_ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            results = {
                'valid': True,
                'errors': [],
                'warnings': [],
                'chain': [],
                'details': {}
            }
            
            # Check if certificate is a CA certificate
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                ).value
                is_ca = basic_constraints.ca
            except:
                is_ca = False
            
            if is_ca:
                # This is a CA certificate (Root or Intermediate)
                if cert.subject == cert.issuer:
                    # Self-signed (Root CA)
                    results['chain'] = ['Root CA (Self-Signed)']
                    results['details']['certificate_type'] = 'Root CA'
                    results['details']['self_signed'] = True
                else:
                    # Intermediate CA
                    results['chain'] = ['Intermediate CA', 'Root CA']
                    results['details']['certificate_type'] = 'Intermediate CA'
                    results['details']['self_signed'] = False
                    
                    # Verify Intermediate is signed by Root
                    try:
                        from cryptography.hazmat.primitives.asymmetric import padding
                        root_ca_cert.public_key().verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            cert.signature_hash_algorithm
                        )
                        results['details']['signed_by_root'] = True
                    except Exception as e:
                        results['valid'] = False
                        results['errors'].append(f'Intermediate CA signature verification failed: {str(e)}')
                        results['details']['signed_by_root'] = False
            else:
                # End-entity certificate
                results['chain'] = ['End-Entity Certificate', 'Intermediate CA', 'Root CA']
                results['details']['certificate_type'] = 'End-Entity'
                results['details']['self_signed'] = False
                
                # Verify certificate is signed by Intermediate CA
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding
                    int_ca_cert.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                    results['details']['signed_by_intermediate'] = True
                except Exception as e:
                    results['valid'] = False
                    results['errors'].append(f'Certificate signature verification failed: {str(e)}')
                    results['details']['signed_by_intermediate'] = False
                
                # Verify Intermediate CA is signed by Root CA
                try:
                    from cryptography.hazmat.primitives.asymmetric import padding
                    root_ca_cert.public_key().verify(
                        int_ca_cert.signature,
                        int_ca_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        int_ca_cert.signature_hash_algorithm
                    )
                    results['details']['intermediate_signed_by_root'] = True
                except Exception as e:
                    results['valid'] = False
                    results['errors'].append(f'Intermediate CA signature verification failed: {str(e)}')
                    results['details']['intermediate_signed_by_root'] = False
            
            # Check certificate validity dates
            now = datetime.utcnow()
            if now < cert.not_valid_before:
                results['valid'] = False
                results['errors'].append('Certificate not yet valid')
                results['details']['not_yet_valid'] = True
            elif now > cert.not_valid_after:
                results['valid'] = False
                results['errors'].append('Certificate has expired')
                results['details']['expired'] = True
            else:
                results['details']['validity_ok'] = True
                
                # Check if expiring soon (within 30 days)
                days_until_expiry = (cert.not_valid_after - now).days
                if days_until_expiry <= 30:
                    results['warnings'].append(f'Certificate expires in {days_until_expiry} days')
                    results['details']['expiring_soon'] = True
            
            # Check Intermediate CA validity
            if now > int_ca_cert.not_valid_after:
                results['valid'] = False
                results['errors'].append('Intermediate CA has expired')
            
            # Check Root CA validity
            if now > root_ca_cert.not_valid_after:
                results['valid'] = False
                results['errors'].append('Root CA has expired')
            
            # Add certificate details
            results['details']['subject'] = cert.subject.rfc4514_string()
            results['details']['issuer'] = cert.issuer.rfc4514_string()
            results['details']['serial_number'] = format(cert.serial_number, 'x')
            results['details']['not_before'] = cert.not_valid_before.isoformat()
            results['details']['not_after'] = cert.not_valid_after.isoformat()
            results['details']['signature_algorithm'] = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'Unknown'
            
            return results
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f'Certificate chain verification failed: {str(e)}'],
                'warnings': [],
                'chain': [],
                'details': {}
            }
