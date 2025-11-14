"""
Database models for PKI/KMS system
"""
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
import json

class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # admin, user, viewer
    is_active = db.Column(db.Boolean, default=True)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    def __repr__(self):
        return f'<User {self.username}>'

class Certificate(db.Model):
    """Certificate model"""
    __tablename__ = 'certificates'
    
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    common_name = db.Column(db.String(255), nullable=False, index=True)
    subject = db.Column(db.Text, nullable=False)
    issuer = db.Column(db.Text, nullable=False)
    cert_type = db.Column(db.String(20), nullable=False)  # server, client, email, code_signing, ca
    key_algorithm = db.Column(db.String(20), default='RSA')
    key_size = db.Column(db.Integer, default=2048)
    hash_algorithm = db.Column(db.String(20), default='SHA256')
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='active')  # active, revoked, expired
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(100), nullable=True)
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_path = db.Column(db.String(500), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    created_by = db.relationship('User', backref='certificates')
    parent = db.relationship('Certificate', remote_side=[id], backref='children')
    
    def is_expired(self):
        """Check if certificate is expired"""
        return datetime.utcnow() > self.not_after
    
    def days_until_expiry(self):
        """Get days until expiry"""
        delta = self.not_after - datetime.utcnow()
        return delta.days if delta.days > 0 else 0
    
    def __repr__(self):
        return f'<Certificate {self.common_name} ({self.serial_number})>'

class Key(db.Model):
    """Key model for KMS"""
    __tablename__ = 'keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    key_type = db.Column(db.String(20), nullable=False)  # symmetric, asymmetric
    algorithm = db.Column(db.String(50), nullable=False)
    key_size = db.Column(db.Integer, nullable=True)
    purpose = db.Column(db.String(50), nullable=False)  # encryption, signing, key_wrapping
    status = db.Column(db.String(20), default='active')  # active, rotating, disabled, deleted
    encrypted_key_material = db.Column(db.LargeBinary, nullable=False)
    version = db.Column(db.Integer, default=1)
    rotation_policy_days = db.Column(db.Integer, nullable=True)
    last_rotated_at = db.Column(db.DateTime, nullable=True)
    next_rotation_at = db.Column(db.DateTime, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accessed_count = db.Column(db.Integer, default=0)
    last_accessed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    created_by = db.relationship('User', backref='keys')
    
    def needs_rotation(self):
        """Check if key needs rotation"""
        if not self.next_rotation_at:
            return False
        return datetime.utcnow() >= self.next_rotation_at
    
    def days_until_rotation(self):
        """Get days until rotation"""
        if not self.next_rotation_at:
            return None
        delta = self.next_rotation_at - datetime.utcnow()
        return delta.days if delta.days > 0 else 0
    
    def __repr__(self):
        return f'<Key {self.name} ({self.key_id})>'

class AuditLog(db.Model):
    """Audit log model"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    event_category = db.Column(db.String(20), nullable=False)  # pki, kms, auth, system
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    resource_type = db.Column(db.String(50), nullable=True)
    resource_id = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # success, failure
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')
    
    @staticmethod
    def log_event(event_type, category, action, status, user=None, ip_address=None, 
                   resource_type=None, resource_id=None, details=None):
        """Create audit log entry"""
        log = AuditLog(
            event_type=event_type,
            event_category=category,
            user_id=user.id if user else None,
            username=user.username if user else 'system',
            ip_address=ip_address,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            status=status,
            details=json.dumps(details) if details else None
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def __repr__(self):
        return f'<AuditLog {self.event_type} by {self.username} at {self.timestamp}>'

class CertificateRevocation(db.Model):
    """Certificate Revocation List entries"""
    __tablename__ = 'certificate_revocations'
    
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey('certificates.id'), nullable=False)
    serial_number = db.Column(db.String(40), nullable=False, index=True)
    revocation_date = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(100), nullable=True)
    revoked_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    certificate = db.relationship('Certificate', backref='revocations')
    revoked_by = db.relationship('User', backref='revocations')
    
    def __repr__(self):
        return f'<Revocation {self.serial_number}>'

class KeyVersion(db.Model):
    """Key version history for rotation tracking"""
    __tablename__ = 'key_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.Integer, db.ForeignKey('keys.id'), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    encrypted_key_material = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deactivated_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    
    # Relationships
    key = db.relationship('Key', backref='versions')
    
    def __repr__(self):
        return f'<KeyVersion {self.key_id} v{self.version}>'

class SystemSetting(db.Model):
    """System settings storage"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False, index=True)  # pki, kms, security
    key = db.Column(db.String(100), nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)
    value_type = db.Column(db.String(20), default='string')  # string, integer, boolean, json
    description = db.Column(db.Text, nullable=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    updated_by = db.relationship('User', backref='settings_updates')
    
    # Unique constraint on category + key
    __table_args__ = (db.UniqueConstraint('category', 'key', name='_category_key_uc'),)
    
    @staticmethod
    def get_setting(category, key, default=None):
        """Get a setting value"""
        setting = SystemSetting.query.filter_by(category=category, key=key).first()
        if not setting:
            return default
        
        # Convert value based on type
        if setting.value_type == 'integer':
            return int(setting.value)
        elif setting.value_type == 'boolean':
            return setting.value.lower() in ('true', '1', 'yes')
        elif setting.value_type == 'json':
            return json.loads(setting.value)
        else:
            return setting.value
    
    @staticmethod
    def set_setting(category, key, value, value_type='string', description=None, user=None):
        """Set or update a setting"""
        setting = SystemSetting.query.filter_by(category=category, key=key).first()
        
        # Convert value to string for storage
        if value_type == 'json':
            value_str = json.dumps(value)
        else:
            value_str = str(value)
        
        if setting:
            setting.value = value_str
            setting.value_type = value_type
            setting.updated_by_id = user.id if user else None
            setting.updated_at = datetime.utcnow()
            if description:
                setting.description = description
        else:
            setting = SystemSetting(
                category=category,
                key=key,
                value=value_str,
                value_type=value_type,
                description=description,
                updated_by_id=user.id if user else None
            )
            db.session.add(setting)
        
        db.session.commit()
        return setting
    
    @staticmethod
    def get_all_by_category(category):
        """Get all settings for a category"""
        settings = SystemSetting.query.filter_by(category=category).all()
        result = {}
        for setting in settings:
            result[setting.key] = SystemSetting.get_setting(category, setting.key)
        return result
    
    def __repr__(self):
        return f'<SystemSetting {self.category}.{self.key}>'
