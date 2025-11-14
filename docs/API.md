# 🔌 REST API Documentation

## Base URL
```
http://localhost:5000/api/v1
```

## Authentication
Currently using session-based authentication. API key authentication available for automation.

---

## 📜 Certificate Endpoints

### List Certificates
```http
GET /api/v1/certificates
```

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (default: 20)
- `status` (string): Filter by status (active, revoked, expired)

**Response:**
```json
{
  "certificates": [
    {
      "id": 1,
      "serial_number": "abc123...",
      "common_name": "server.example.com",
      "type": "server",
      "status": "active",
      "not_before": "2025-01-01T00:00:00",
      "not_after": "2026-01-01T00:00:00",
      "days_until_expiry": 365,
      "created_at": "2025-01-01T00:00:00"
    }
  ],
  "total": 10,
  "pages": 1,
  "current_page": 1
}
```

### Create Certificate
```http
POST /api/v1/certificates
```

**Request Body:**
```json
{
  "common_name": "server.example.com",
  "type": "server",
  "validity_days": 365,
  "key_size": 2048,
  "san_list": ["www.example.com", "api.example.com"],
  "organization": "My Company"
}
```

**Response:**
```json
{
  "success": true,
  "certificate": {
    "id": 1,
    "serial_number": "abc123...",
    "common_name": "server.example.com",
    "not_after": "2026-01-01T00:00:00",
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

### Get Certificate
```http
GET /api/v1/certificates/{id}
```

**Response:**
```json
{
  "id": 1,
  "serial_number": "abc123...",
  "common_name": "server.example.com",
  "subject": "CN=server.example.com,O=...",
  "issuer": "CN=Intermediate CA,O=...",
  "type": "server",
  "status": "active",
  "not_before": "2025-01-01T00:00:00",
  "not_after": "2026-01-01T00:00:00",
  "days_until_expiry": 365,
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "created_at": "2025-01-01T00:00:00"
}
```

### Revoke Certificate
```http
POST /api/v1/certificates/{id}/revoke
```

**Request Body:**
```json
{
  "reason": "key_compromise"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate revoked"
}
```

---

## 🔑 Key Management Endpoints

### List Keys
```http
GET /api/v1/keys
```

**Query Parameters:**
- `page` (int): Page number
- `per_page` (int): Items per page
- `status` (string): Filter by status (active, disabled)

**Response:**
```json
{
  "keys": [
    {
      "id": 1,
      "key_id": "xyz789...",
      "name": "encryption-key",
      "type": "symmetric",
      "algorithm": "AES-256",
      "purpose": "encryption",
      "status": "active",
      "version": 1,
      "created_at": "2025-01-01T00:00:00",
      "days_until_rotation": 30
    }
  ],
  "total": 5,
  "pages": 1,
  "current_page": 1
}
```

### Create Key
```http
POST /api/v1/keys
```

**Request Body:**
```json
{
  "name": "my-encryption-key",
  "type": "symmetric",
  "algorithm": "AES-256",
  "purpose": "encryption",
  "rotation_policy_days": 90,
  "description": "Application encryption key"
}
```

**Response:**
```json
{
  "success": true,
  "key": {
    "id": 1,
    "key_id": "xyz789...",
    "name": "my-encryption-key",
    "algorithm": "AES-256",
    "purpose": "encryption",
    "created_at": "2025-01-01T00:00:00"
  }
}
```

### Get Key Details
```http
GET /api/v1/keys/{id}
```

**Response:**
```json
{
  "id": 1,
  "key_id": "xyz789...",
  "name": "my-encryption-key",
  "description": "Application encryption key",
  "type": "symmetric",
  "algorithm": "AES-256",
  "purpose": "encryption",
  "status": "active",
  "version": 1,
  "rotation_policy_days": 90,
  "next_rotation_at": "2025-04-01T00:00:00",
  "created_at": "2025-01-01T00:00:00",
  "accessed_count": 42
}
```

### Encrypt Data
```http
POST /api/v1/keys/{id}/encrypt
```

**Request Body:**
```json
{
  "plaintext": "Secret data to encrypt"
}
```

**Response:**
```json
{
  "success": true,
  "encrypted_data": {
    "key_id": "xyz789...",
    "iv": "base64-encoded-iv",
    "tag": "base64-encoded-tag",
    "ciphertext": "base64-encoded-ciphertext"
  }
}
```

### Decrypt Data
```http
POST /api/v1/keys/{id}/decrypt
```

**Request Body:**
```json
{
  "encrypted_data": {
    "key_id": "xyz789...",
    "iv": "base64-encoded-iv",
    "tag": "base64-encoded-tag",
    "ciphertext": "base64-encoded-ciphertext"
  }
}
```

**Response:**
```json
{
  "success": true,
  "plaintext": "Secret data to encrypt"
}
```

---

## 📊 System Endpoints

### Get Statistics
```http
GET /api/v1/stats
```

**Response:**
```json
{
  "certificates": {
    "total": 100,
    "active": 85,
    "revoked": 10,
    "expired": 5,
    "expiring_soon": 8
  },
  "keys": {
    "total": 50,
    "active": 45,
    "rotation_due": 3
  },
  "users": {
    "total": 15,
    "active": 12
  }
}
```

### API Documentation
```http
GET /api/v1/docs
```

Returns API documentation with all available endpoints.

---

## 💡 Usage Examples

### PowerShell

```powershell
# Set headers
$headers = @{
    "Content-Type" = "application/json"
}

# Create certificate
$certBody = @{
    common_name = "api.example.com"
    type = "server"
    validity_days = 365
    san_list = @("www.example.com", "api.example.com")
} | ConvertTo-Json

$cert = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/certificates" `
    -Method Post -Headers $headers -Body $certBody

Write-Host "Certificate created: $($cert.certificate.serial_number)"

# Create key
$keyBody = @{
    name = "app-encryption-key"
    algorithm = "AES-256"
    purpose = "encryption"
} | ConvertTo-Json

$key = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/keys" `
    -Method Post -Headers $headers -Body $keyBody

Write-Host "Key created: $($key.key.key_id)"

# Encrypt data
$encryptBody = @{
    plaintext = "My secret data"
} | ConvertTo-Json

$encrypted = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/keys/$($key.key.id)/encrypt" `
    -Method Post -Headers $headers -Body $encryptBody

# Decrypt data
$decryptBody = @{
    encrypted_data = $encrypted.encrypted_data
} | ConvertTo-Json

$decrypted = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/keys/$($key.key.id)/decrypt" `
    -Method Post -Headers $headers -Body $decryptBody

Write-Host "Decrypted: $($decrypted.plaintext)"

# Get stats
$stats = Invoke-RestMethod -Uri "http://localhost:5000/api/v1/stats"
Write-Host "Total Certificates: $($stats.certificates.total)"
Write-Host "Total Keys: $($stats.keys.total)"
```

### Python

```python
import requests
import json

base_url = "http://localhost:5000/api/v1"
headers = {"Content-Type": "application/json"}

# Create certificate
cert_data = {
    "common_name": "api.example.com",
    "type": "server",
    "validity_days": 365,
    "san_list": ["www.example.com", "api.example.com"]
}

response = requests.post(
    f"{base_url}/certificates",
    headers=headers,
    json=cert_data
)

cert = response.json()
print(f"Certificate created: {cert['certificate']['serial_number']}")

# Create key
key_data = {
    "name": "app-encryption-key",
    "algorithm": "AES-256",
    "purpose": "encryption"
}

response = requests.post(
    f"{base_url}/keys",
    headers=headers,
    json=key_data
)

key = response.json()
key_id = key['key']['id']
print(f"Key created: {key['key']['key_id']}")

# Encrypt data
encrypt_data = {"plaintext": "My secret data"}
response = requests.post(
    f"{base_url}/keys/{key_id}/encrypt",
    headers=headers,
    json=encrypt_data
)

encrypted = response.json()['encrypted_data']

# Decrypt data
decrypt_data = {"encrypted_data": encrypted}
response = requests.post(
    f"{base_url}/keys/{key_id}/decrypt",
    headers=headers,
    json=decrypt_data
)

decrypted = response.json()
print(f"Decrypted: {decrypted['plaintext']}")

# Get stats
response = requests.get(f"{base_url}/stats")
stats = response.json()
print(f"Total Certificates: {stats['certificates']['total']}")
print(f"Total Keys: {stats['keys']['total']}")
```

### cURL

```bash
# Create certificate
curl -X POST http://localhost:5000/api/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "api.example.com",
    "type": "server",
    "validity_days": 365
  }'

# List certificates
curl http://localhost:5000/api/v1/certificates

# Create key
curl -X POST http://localhost:5000/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-key",
    "algorithm": "AES-256",
    "purpose": "encryption"
  }'

# Get stats
curl http://localhost:5000/api/v1/stats
```

---

## 🔒 Security Notes

- Always use HTTPS in production
- Implement API key authentication for automation
- Rate limit API endpoints
- Validate all input data
- Log all API access for audit
- Use proper CORS settings

---

## 📝 Error Responses

All errors return appropriate HTTP status codes:

```json
{
  "error": "Error message description"
}
```

**Common Status Codes:**
- `200 OK` - Success
- `201 Created` - Resource created
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication required
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## 🔄 Rate Limiting

Default rate limit: 100 requests per hour per IP

Can be configured in `config/config.yaml`:
```yaml
security:
  api:
    rate_limit: "100 per hour"
```

---

For more information, visit the interactive API documentation at:
**http://localhost:5000/api/v1/docs**
