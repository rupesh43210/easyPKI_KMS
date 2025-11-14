# 🚀 PKI/KMS System - Ultra Quick Start

## The Simplest Way (ONE Command!)

### Just Run This:

**PowerShell:**
```powershell
.\start.ps1
```

**Command Prompt:**
```cmd
start.bat
```

**Double-click:** `start.bat` in Windows Explorer

---

## What Happens Automatically? ✨

The smart startup script will:

1. ✅ **Check Python** - Verify Python is installed
2. ✅ **Create venv** - Create virtual environment (first time only)
3. ✅ **Activate venv** - Activate it automatically
4. ✅ **Install packages** - Install dependencies (first time only)
5. ✅ **Initialize system** - Set up database and CA (first time only)
6. ✅ **Start server** - Launch the web application

**You don't need to do anything else!**

---

## First Run vs. Every Other Run

### First Time You Run:
```powershell
.\start.ps1
```

**What it does:**
- Creates `venv/` folder
- Installs all Python packages (~30 seconds)
- Creates database and CA certificates
- Starts the server

**Takes:** ~1-2 minutes (one time only)

### Every Time After:
```powershell
.\start.ps1
```

**What it does:**
- Detects existing venv ✅
- Detects installed packages ✅
- Detects initialized system ✅
- Starts the server immediately

**Takes:** ~2-3 seconds ⚡

---

## Access Your System

Once the server starts, you'll see:

```
========================================
  Starting PKI/KMS Server
========================================

Access at: http://localhost:5000
Username: admin
Password: admin123

⚠️  Change password after first login!

Press Ctrl+C to stop the server
========================================
```

**Open your browser:** http://localhost:5000

---

## Stop the Server

**Press:** `Ctrl + C` in the terminal

---

## Troubleshooting

### "Python not found"
**Solution:** Install Python 3.8+ from https://www.python.org/downloads/
- ✅ Check "Add Python to PATH" during installation

### PowerShell Script Blocked
**Solution:** Run once as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Port 5000 Already in Use
**Solution:** Edit `config/config.yaml` and change the port:
```yaml
app:
  port: 8080  # Change to any available port
```

### Want to Start Fresh
**Solution:** Delete these folders and run again:
```powershell
Remove-Item -Recurse -Force venv, data
.\start.ps1
```

---

## Daily Workflow

**Every day, just:**

```powershell
# Open PowerShell in the pki folder
.\start.ps1

# That's it! 🎉
```

---

## CLI Tools Usage

**The venv is activated automatically when you run `start.ps1`**

Open a **new terminal** in the same folder:

```powershell
# Activate venv manually
.\venv\Scripts\Activate.ps1

# Now use CLI tools
python cli\pki_tool.py cert list
python cli\kms_tool.py key list
```

---

## What Gets Created (First Run)

```
pki/
├── venv/                    # Virtual environment (auto-created)
├── data/                    # Database and certificates (auto-created)
│   ├── ca/                 # Root and Intermediate CA
│   ├── certs/              # Issued certificates
│   ├── keys/               # Managed keys
│   └── logs/               # Log files
└── ... (your project files)
```

---

## Comparison: This vs. Manual Setup

| Task | Manual Way | Smart Script Way |
|------|-----------|------------------|
| Create venv | `python -m venv venv` | **Automatic** ✅ |
| Activate venv | `.\venv\Scripts\Activate.ps1` | **Automatic** ✅ |
| Install packages | `pip install -r requirements.txt` | **Automatic** ✅ |
| Initialize | `python cli\init_pki.py` | **Automatic** ✅ |
| Start server | `python run.py` | **Automatic** ✅ |
| **Total commands** | **5 commands** | **1 command** ✨ |

---

## Advanced: Other Startup Scripts

If you want more control, you can use:

| Script | Purpose |
|--------|---------|
| `start.ps1` / `start.bat` | **Smart startup (RECOMMENDED)** ⭐ |
| `setup_venv.ps1` | Manual setup only (without starting) |
| `start_with_venv.ps1` | Start only (assumes setup done) |

**But you probably just need `start.ps1`!** 🎯

---

## FAQ

**Q: Do I need to run setup_venv.ps1 first?**  
**A:** No! Just run `start.ps1` - it does everything.

**Q: What if I want to update dependencies?**  
**A:** Delete `venv/` folder and run `start.ps1` again.

**Q: Can I use this in production?**  
**A:** Yes, but use a production WSGI server like Gunicorn and proper secrets.

**Q: Do I need to activate venv every time?**  
**A:** No! `start.ps1` does it automatically.

---

## 🎉 Summary

**All you need to remember:**

```powershell
.\start.ps1
```

**That's literally it!** The script handles everything else automatically. 🚀

---

**Next:** Open http://localhost:5000 and start using your PKI/KMS system!
