# GPG Key Management Features

## 🔐 Overview

Your PKI/KMS system now includes full **GPG (GNU Privacy Guard)** key management capabilities!

## ✨ Features Added

### 🔑 Key Management
- **Generate GPG Keys**: RSA (2048/3072/4096-bit), DSA, ECDSA
- **Import/Export Keys**: Public and private keys in ASCII armor format
- **List Keys**: View all public and private GPG keys
- **Delete Keys**: Remove keys from keyring
- **Key Information**: Detailed metadata for each key

### 🔒 Encryption & Decryption
- **Encrypt Data**: Encrypt for multiple recipients
- **Decrypt Data**: Decrypt encrypted messages
- **Sign & Encrypt**: Combine signing with encryption

### ✍️ Digital Signatures
- **Sign Data**: Create digital signatures
- **Verify Signatures**: Validate signed data
- **Detached Signatures**: Separate signature files
- **Clearsign**: Human-readable signed messages

## 📦 Installation

The GPG library has been added to `requirements.txt`. Install it:

```powershell
# If using virtual environment
.\venv\Scripts\Activate.ps1
pip install python-gnupg==0.5.2

# Or reinstall all dependencies
pip install -r requirements.txt
```

**Note**: Requires GPG to be installed on your system:
- **Windows**: Download from https://www.gpg4win.org/
- **Linux**: `sudo apt-get install gnupg` (usually pre-installed)
- **macOS**: `brew install gnupg`

## 🚀 Usage Examples

### Python API Usage

```python
from app.gpg import GPGManager

# Initialize GPG Manager
gpg = GPGManager()

# Generate a new GPG key pair
key_info = gpg.generate_key(
    name_real="John Doe",
    name_email="john@example.com",
    name_comment="My GPG Key",
    key_type="RSA",
    key_length=4096,
    expire_date="2026-12-31",  # or "0" for never
    passphrase="strong_passphrase"
)

print(f"Generated key: {key_info['fingerprint']}")

# List all public keys
public_keys = gpg.list_keys()
for key in public_keys:
    print(f"Key ID: {key['key_id']}, UIDs: {key['uids']}")

# List private keys
private_keys = gpg.list_keys(secret=True)

# Export public key
public_key = gpg.export_public_key(fingerprint)
print(public_key)  # ASCII armored public key

# Export private key (requires passphrase)
private_key = gpg.export_private_key(
    fingerprint,
    passphrase="strong_passphrase"
)

# Import a key
key_data = """-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----"""
result = gpg.import_key(key_data)
print(f"Imported {result['count']} keys")

# Encrypt data
encrypted = gpg.encrypt(
    data="Sensitive information",
    recipients=["john@example.com"],  # Can be email or fingerprint
    armor=True
)
print(encrypted)

# Encrypt and sign
encrypted_signed = gpg.encrypt(
    data="Sensitive information",
    recipients=["john@example.com"],
    sign=fingerprint,  # Sign with your key
    passphrase="strong_passphrase"
)

# Decrypt data
decrypted, metadata = gpg.decrypt(
    encrypted_data=encrypted,
    passphrase="strong_passphrase"
)
print(f"Decrypted: {decrypted}")
print(f"Signed by: {metadata['username']}")

# Sign data (detached signature)
signature = gpg.sign(
    data="Important message",
    keyid=fingerprint,
    passphrase="strong_passphrase",
    detach=True
)

# Sign data (clearsign - readable with signature)
clearsigned = gpg.sign(
    data="Important message",
    keyid=fingerprint,
    passphrase="strong_passphrase",
    clearsign=True
)

# Verify signature
verification = gpg.verify(clearsigned)
if verification['valid']:
    print(f"Valid signature from: {verification['username']}")
    print(f"Fingerprint: {verification['fingerprint']}")
else:
    print("Invalid signature!")

# Verify detached signature
verification = gpg.verify(
    signed_data="Important message",
    signature=signature
)

# Delete a key
gpg.delete_key(fingerprint, secret=False)  # Delete public key
gpg.delete_key(fingerprint, secret=True, passphrase="pass")  # Delete private key
```

## 🌐 Web Interface (Coming Soon)

GPG key management UI will be added to the web dashboard with:
- Generate keys through web form
- Upload/import keys
- Export keys
- Encrypt/decrypt files
- Sign and verify documents

## 🔌 REST API (Coming Soon)

GPG endpoints will be added to the REST API:

```powershell
# Generate GPG key
POST /api/v1/gpg/keys
{
  "name": "John Doe",
  "email": "john@example.com",
  "key_type": "RSA",
  "key_length": 4096,
  "passphrase": "strong_pass"
}

# List keys
GET /api/v1/gpg/keys

# Export public key
GET /api/v1/gpg/keys/{fingerprint}/public

# Encrypt data
POST /api/v1/gpg/encrypt
{
  "data": "secret message",
  "recipients": ["john@example.com"]
}

# Decrypt data
POST /api/v1/gpg/decrypt
{
  "encrypted_data": "-----BEGIN PGP MESSAGE-----...",
  "passphrase": "strong_pass"
}

# Sign data
POST /api/v1/gpg/sign
{
  "data": "important message",
  "keyid": "ABC123...",
  "passphrase": "strong_pass"
}

# Verify signature
POST /api/v1/gpg/verify
{
  "signed_data": "-----BEGIN PGP SIGNED MESSAGE-----..."
}
```

## 🛠️ CLI Tool (Coming Soon)

```powershell
# Generate key
python cli/gpg_tool.py generate --name "John Doe" --email john@example.com

# List keys
python cli/gpg_tool.py list

# Export key
python cli/gpg_tool.py export --fingerprint ABC123 --output key.asc

# Encrypt file
python cli/gpg_tool.py encrypt --file document.txt --recipient john@example.com

# Decrypt file
python cli/gpg_tool.py decrypt --file document.txt.gpg

# Sign file
python cli/gpg_tool.py sign --file document.txt --key ABC123

# Verify signature
python cli/gpg_tool.py verify --file document.txt.sig
```

## 🔒 Security Best Practices

1. **Strong Passphrases**: Use long, complex passphrases for private keys
2. **Key Expiration**: Set expiration dates for keys (e.g., 1-2 years)
3. **Backup Keys**: Securely backup private keys offline
4. **Revocation Certificates**: Generate revocation certs when creating keys
5. **Key Signing**: Sign keys you've verified (web of trust)
6. **Secure Storage**: Keep private keys in encrypted storage
7. **Regular Rotation**: Rotate keys periodically
8. **Separate Keys**: Use different keys for different purposes (signing vs encryption)

## 📚 GPG Key Types

| Type | Bits | Use Case |
|------|------|----------|
| RSA | 2048 | Minimum recommended |
| RSA | 3072 | Good balance |
| RSA | 4096 | Maximum security |
| DSA | 2048 | Legacy, signing only |
| ECDSA | 256 | Elliptic curve, modern |

## 🎯 Use Cases

- **Email Encryption**: Encrypt emails with GPG
- **File Encryption**: Secure sensitive files
- **Code Signing**: Sign software releases
- **Document Signing**: Digital signatures for contracts
- **SSH Authentication**: Use GPG keys for SSH
- **Git Commit Signing**: Sign git commits and tags
- **Password Manager**: Encrypt password databases

## 📖 Resources

- [GPG Manual](https://www.gnupg.org/documentation/)
- [GPG Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)
- [Key Management](https://security.stackexchange.com/questions/tagged/gpg)

## ✅ Next Steps

1. Install GPG on your system
2. Install python-gnupg: `pip install python-gnupg`
3. Test key generation with the Python API examples above
4. Wait for web UI and REST API implementation (coming soon!)

---

**GPG Feature Status**: 🟢 **Core module completed!**
- ✅ Python library integrated
- ✅ Core GPG manager implemented
- ⏳ Web UI (planned)
- ⏳ REST API endpoints (planned)
- ⏳ CLI tool (planned)
