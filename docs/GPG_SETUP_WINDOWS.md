# PGP/GPG Setup Instructions for Windows

## Problem
The PGP/GPG functionality requires the GPG binary to be installed on your system. Currently, it's not found.

## Solution - Install GPG4Win (Gpg4win)

### Option 1: Download from Official Source
1. Download **Gpg4win** from: https://gpg4win.org/download.html
2. Run the installer
3. Make sure to check "Add to PATH" during installation
4. Restart your terminal/PowerShell after installation

### Option 2: Using Chocolatey (if you have it installed)
```powershell
choco install gpg4win
```

### Option 3: Using winget
```powershell
winget install GnuPG.Gpg4win
```

## Verify Installation

After installation, verify GPG is available:
```powershell
gpg --version
```

You should see output like:
```
gpg (GnuPG) 2.x.x
...
```

## Alternative: Disable PGP/GPG Features

If you don't need PGP/GPG functionality right now, you can:
1. Comment out the PGP/GPG tab in the UI
2. The PKI/KMS features will work fine without it
3. Install GPG later when needed

## Test After Installation

1. Restart your terminal/PowerShell
2. Activate venv:
   ```powershell
   cd "C:\Users\zuu1kor\OneDrive - Bosch Group\Projects\MiDAS\Code\pki"
   .\venv\Scripts\Activate.ps1
   ```

3. Test GPG:
   ```powershell
   python -c "from app.gpg import GPGManager; gpg = GPGManager(); print('✅ GPG works!')"
   ```

## Documentation

Once installed, you can:
- Generate PGP/GPG keys
- Import/Export keys
- Encrypt/Decrypt messages
- Sign/Verify signatures
- Full compatibility with PGP Desktop, Thunderbird, ProtonMail, etc.

## Notes

- **python-gnupg** (already installed in venv) is just a Python wrapper
- It requires the actual **GPG binary** (gpg.exe) to be on your system
- GPG4Win includes both command-line and GUI tools (Kleopatra)
