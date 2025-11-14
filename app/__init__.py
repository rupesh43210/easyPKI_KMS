"""
PKI/KMS Application Package
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS
import os
from pathlib import Path

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

def create_app(config):
    """Application factory"""
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')
    
    # Configure app
    app.config['SECRET_KEY'] = config['app']['secret_key']
    
    # Convert relative database URI to absolute path
    db_uri = config['database']['uri']
    if db_uri.startswith('sqlite:///') and not db_uri.startswith('sqlite:////'):
        # Relative path - convert to absolute
        db_path = db_uri.replace('sqlite:///', '')
        abs_db_path = os.path.abspath(db_path)
        db_uri = f'sqlite:///{abs_db_path}'
    
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = config['database']['echo']
    
    # Store config in app
    app.config['PKI_CONFIG'] = config
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'web.login'
    CORS(app)
    
    # Create necessary directories
    create_directories(config)
    
    # Register blueprints
    from app.web.routes import web_bp
    from app.api.routes import api_bp
    
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    return app

def init_database():
    """Initialize database with tables and default data"""
    from app.models import User, Certificate, Key, AuditLog
    
    # Create all tables
    db.create_all()
    
    # Create default admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        from app.models import User
        admin = User(
            username='admin',
            email='admin@example.com',
            role='admin'
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin user created (username: admin, password: admin123)")

def create_directories(config):
    """Create necessary directories"""
    paths = [
        config['storage']['ca_path'],
        config['storage']['certs_path'],
        config['storage']['keys_path'],
        config['storage']['backups_path'],
        config['storage']['logs_path']
    ]
    
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    from app.models import User
    return User.query.get(int(user_id))
