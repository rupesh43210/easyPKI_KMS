# 🔐 Enterprise PKI/KMS System

A comprehensive, production-ready Public Key Infrastructure (PKI) and Key Management System (KMS) with an intuitive web interface, powerful REST API, and full CLI tooling.

## 🚀 Quick Start

**Just run one command:**
```powershell
.\start.ps1
```

That's it! The script automatically:
- ✅ Detects/creates virtual environment
- ✅ Installs dependencies
- ✅ Initializes PKI and KMS
- ✅ Starts the web server

Access the dashboard at **http://localhost:5000**

Default login: `admin` / `admin` (change immediately!)

---

## ✨ Key Features

### 🔑 PKI Capabilities (150+ Features)
- **Certificate Authority**: Root CA + Intermediate CA (4096-bit RSA)
- **Certificate Types**: Server (TLS/SSL), Client, Email (S/MIME), Code Signing
- **Lifecycle Management**: Issue, Renew, Revoke, CRL, OCSP
- **Advanced**: SAN support, Key Usage extensions, Chain validation

### 🛡️ KMS Capabilities
- **Symmetric Keys**: AES-128/192/256-GCM encryption
- **Asymmetric Keys**: RSA (2048/4096), ECC (P-256/384/521)
- **Operations**: Generate, Encrypt, Decrypt, Sign, Verify
- **Management**: Key rotation, versioning, access control, audit trails

### 🌐 Interfaces
- **Web Dashboard**: Modern Bootstrap 5 UI with real-time stats
- **REST API**: Full CRUD operations ([API Docs](docs/API.md))
- **CLI Tools**: `pki_tool.py`, `kms_tool.py` for automation

---

## 📁 Project Structure

```
pki/
├── app/                    # Core application
│   ├── __init__.py        # App factory
│   ├── models.py          # Database models
│   ├── api/               # REST API endpoints
│   │   └── routes.py
│   ├── web/               # Web interface
│   │   └── routes.py
│   ├── pki/               # PKI engine
│   │   └── ca.py
│   ├── kms/               # KMS engine
│   │   └── kms.py
│   └── utils/             # Helper utilities
├── cli/                   # Command-line tools
│   ├── init_pki.py
│   ├── pki_tool.py
│   └── kms_tool.py
├── config/                # Configuration
│   └── config.yaml
├── data/                  # Storage (auto-created)
│   ├── ca/               # CA certificates & keys
│   ├── certs/            # Issued certificates
│   └── keys/             # Managed keys
├── docs/                  # Documentation
│   ├── API.md            # REST API guide
│   ├── START_HERE.md     # Getting started
│   ├── FEATURES.md       # Feature list
│   └── QUICK_REF.txt     # Quick reference
├── templates/            # HTML templates
├── static/               # CSS/JS assets
├── start.ps1             # Smart startup script (PowerShell)
├── start.bat             # Smart startup script (Batch)
├── requirements.txt      # Python dependencies
└── run.py               # Main entry point
```

---

## 📚 Documentation

- **[Getting Started Guide](docs/START_HERE.md)** - Complete setup walkthrough
- **[Feature List](docs/FEATURES.md)** - All 150+ features explained
- **[REST API Reference](docs/API.md)** - Full API docs with examples
- **[Quick Reference](docs/QUICK_REF.txt)** - Command cheat sheet

---

## 💻 Usage Examples

### 🌐 Web Interface

Navigate to **http://localhost:5000** and use the intuitive dashboard:
- 📜 Create and manage certificates (server, client, email, code signing)
- 🔑 Generate and rotate encryption keys
- 📊 View real-time system statistics
- 🔍 Search and filter certificates
- 📋 Monitor audit logs
- ⚙️ Configure security policies

### 🔌 REST API

**PowerShell Example:**
```powershell
# Create TLS certificate
$cert = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/certificates" `
  -Method Post -ContentType "application/json" -Body (@{
    common_name = "api.example.com"
    type = "server"
    validity_days = 365
    san_list = @("www.example.com", "api.example.com")
} | ConvertTo-Json)

# Create encryption key
$key = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/keys" `
  -Method Post -ContentType "application/json" -Body (@{
    name = "production-key"
    algorithm = "AES-256"
    purpose = "encryption"
} | ConvertTo-Json)

# Encrypt data
$encrypted = Invoke-RestMethod `
  -Uri "http://localhost:5000/api/v1/keys/$($key.key.id)/encrypt" `
  -Method Post -ContentType "application/json" -Body (@{
    plaintext = "Sensitive data"
} | ConvertTo-Json)

# Get statistics
$stats = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/stats"
Write-Host "Total Certificates: $($stats.certificates.total)"
```

**See [API.md](docs/API.md) for Python, cURL, and more examples.**

### 🛠️ CLI Tools

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Certificate management
python cli/pki_tool.py cert create --cn server.example.com --type server
python cli/pki_tool.py cert list --status active
python cli/pki_tool.py cert info --serial ABC123
python cli/pki_tool.py cert revoke --serial ABC123

# Key management
python cli/kms_tool.py key create --name app-key --algorithm AES-256
python cli/kms_tool.py key list
python cli/kms_tool.py key rotate --id 1
python cli/kms_tool.py encrypt --key-id XYZ789 --data "secret"
```

---

## ⚙️ Configuration

Edit `config/config.yaml` to customize:

```yaml
pki:
  root_ca:
    key_size: 4096
    validity_days: 7300  # 20 years
  intermediate_ca:
    key_size: 4096
    validity_days: 3650  # 10 years

kms:
  default_algorithm: "AES-256"
  rotation_policy_days: 90
  key_backup_enabled: true

security:
  password_min_length: 12
  session_timeout_minutes: 30
  api_rate_limit: "100 per hour"

database:
  uri: "sqlite:///data/pki.db"  # Or PostgreSQL/MySQL for production
```

---

## 🔒 Security Best Practices

1. **🔐 Change Default Credentials** - First login: Update `admin/admin` immediately
2. **🌐 Enable HTTPS** - Use TLS certificates for production deployment
3. **💾 Offline Root CA** - Store Root CA in secure, offline location
4. **🔄 Regular Key Rotation** - Implement automated key rotation policies
5. **📋 Audit Logging** - Enable comprehensive audit trails
6. **💿 Backup Strategy** - Regular encrypted backups of CA keys and database
7. **🏦 HSM Integration** - Use Hardware Security Module for production environments
8. **🔍 Access Control** - Implement role-based access control (RBAC)
9. **📊 Monitor Expiry** - Set up alerts for expiring certificates
10. **🔒 Secure Storage** - Encrypt keys at rest with strong encryption

---

## 📦 Requirements

- **Python**: 3.8 or higher
- **OS**: Windows, Linux, macOS
- **Dependencies**: Listed in `requirements.txt` (auto-installed by start scripts)

### Core Dependencies
```
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
cryptography==41.0.7
PyYAML==6.0.1
click==8.1.7
```

---

## 🐛 Troubleshooting

**Virtual environment issues?**
```powershell
# Delete and recreate
Remove-Item -Recurse -Force venv
.\start.ps1  # Will recreate automatically
```

**Dependencies not installing?**
```powershell
# Manual install
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

**Server won't start?**
```powershell
# Check logs
Get-Content logs\pki.log -Tail 50

# Verify port 5000 is free
netstat -ano | findstr :5000
```

**Database errors?**
```powershell
# Reinitialize database
.\venv\Scripts\Activate.ps1
python cli/init_pki.py --force
```

---

## 📞 Support

For issues, feature requests, or questions:
- Check **[docs/START_HERE.md](docs/START_HERE.md)** for setup help
- Review **[docs/QUICK_REF.txt](docs/QUICK_REF.txt)** for command reference
- See **[docs/FEATURES.md](docs/FEATURES.md)** for complete feature list

---

## 📄 License

MIT License - See LICENSE file for details

---

**Built with ❤️ for Enterprise Security**
