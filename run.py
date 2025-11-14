#!/usr/bin/env python3
"""
Main entry point for the PKI/KMS system
"""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app, init_database
from app.utils.logger import setup_logging
from app.utils.config import load_config

def main():
    """Main function to start the application"""
    
    # Load configuration
    config = load_config()
    
    # Setup logging
    setup_logging(config)
    
    # Initialize database
    app = create_app(config)
    
    with app.app_context():
        init_database()
    
    # Start the application
    print("\n" + "="*60)
    print(f"🔐 {config['app']['name']} v{config['app']['version']}")
    print("="*60)
    print(f"\n✅ Server starting on http://{config['app']['host']}:{config['app']['port']}")
    print(f"📊 Dashboard: http://localhost:{config['app']['port']}/")
    print(f"📖 API Docs: http://localhost:{config['app']['port']}/api/docs")
    print("\n⚠️  Default credentials: admin / admin123")
    print("    Please change the password after first login!\n")
    print("="*60 + "\n")
    
    # Run the Flask app
    app.run(
        host=config['app']['host'],
        port=config['app']['port'],
        debug=config['app']['debug'],
        threaded=True
    )

if __name__ == "__main__":
    main()
