#!/usr/bin/env python3
"""
Initialize PKI/KMS system
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, init_database
from app.pki.ca import CertificateAuthority
from app.utils.config import load_config
from app.utils.logger import setup_logging

def main():
    """Initialize the PKI/KMS system"""
    print("\n" + "="*60)
    print("🔐 PKI/KMS System Initialization")
    print("="*60 + "\n")
    
    try:
        # Load configuration
        print("📋 Loading configuration...")
        config = load_config()
        print("✅ Configuration loaded\n")
        
        # Create necessary directories first (before app creation)
        print("📁 Creating directories...")
        import os
        os.makedirs('data', exist_ok=True)
        os.makedirs('data/ca', exist_ok=True)
        os.makedirs('data/certs', exist_ok=True)
        os.makedirs('data/keys', exist_ok=True)
        os.makedirs('data/backups', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        print("✅ Directories created\n")
        
        # Setup logging
        print("📝 Setting up logging...")
        setup_logging(config)
        print("✅ Logging configured\n")
        
        # Create Flask app
        print("🚀 Creating application...")
        app = create_app(config)
        print("✅ Application created\n")
        
        # Initialize database
        print("🗄️  Initializing database...")
        with app.app_context():
            init_database()
        print("✅ Database initialized\n")
        
        # Initialize Certificate Authority
        print("📜 Initializing Certificate Authority...")
        with app.app_context():
            ca = CertificateAuthority(config, config['storage']['ca_path'])
            ca.initialize_ca()
        print("✅ Certificate Authority initialized\n")
        
        print("="*60)
        print("✅ Initialization complete!")
        print("="*60)
        print("\n🎉 Your PKI/KMS system is ready to use!")
        print(f"\nTo start the server, run:")
        print(f"  python run.py")
        print(f"\nDefault credentials:")
        print(f"  Username: admin")
        print(f"  Password: admin123")
        print(f"\n⚠️  Please change the default password after first login!\n")
        
    except Exception as e:
        print(f"\n❌ Initialization failed: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
