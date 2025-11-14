"""
REST API routes
"""
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from app import db
from app.models import Certificate, Key, AuditLog, User
from app.pki.ca import CertificateAuthority
from app.kms.kms import KeyManagementSystem
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import secrets
from functools import wraps

api_bp = Blueprint('api', __name__)

def api_key_required(f):
    """Decorator for API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # For now, use login_required
        # In production, implement API key authentication
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ============= Certificate APIs =============

@api_bp.route('/certificates', methods=['GET'])
@api_key_required
def list_certificates():
    """List all certificates"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = Certificate.query
    
    # Filters
    status = request.args.get('status')
    if status:
        query = query.filter_by(status=status)
    
    certs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'certificates': [{
            'id': c.id,
            'serial_number': c.serial_number,
            'common_name': c.common_name,
            'type': c.cert_type,
            'status': c.status,
            'not_before': c.not_before.isoformat(),
            'not_after': c.not_after.isoformat(),
            'days_until_expiry': c.days_until_expiry(),
            'created_at': c.created_at.isoformat()
        } for c in certs.items],
        'total': certs.total,
        'pages': certs.pages,
        'current_page': certs.page
    })

@api_bp.route('/certificates', methods=['POST'])
@api_key_required
def create_certificate():
    """Create a new certificate"""
    data = request.get_json()
    
    # Validate input
    if not data.get('common_name'):
        return jsonify({'error': 'common_name is required'}), 400
    
    try:
        # Get config
        config = current_app.config['PKI_CONFIG']
        
        # Initialize CA
        ca = CertificateAuthority(config, config['storage']['ca_path'])
        
        # Create certificate
        private_key, cert = ca.create_certificate(
            common_name=data['common_name'],
            cert_type=data.get('type', 'server'),
            validity_days=data.get('validity_days', 365),
            key_size=data.get('key_size', 2048),
            san_list=data.get('san_list'),
            organization=data.get('organization')
        )
        
        # Save to database
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        
        # Save private key
        key_filename = f"{cert.serial_number}.key"
        key_path = Path(config['storage']['certs_path']) / key_filename
        ca._save_certificate_and_key(cert, private_key, 
                                     Path(config['storage']['certs_path']) / f"{cert.serial_number}.crt",
                                     key_path)
        
        db_cert = Certificate(
            serial_number=format(cert.serial_number, 'x'),
            common_name=data['common_name'],
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            cert_type=data.get('type', 'server'),
            key_algorithm='RSA',
            key_size=data.get('key_size', 2048),
            hash_algorithm='SHA256',
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            status='active',
            certificate_pem=cert_pem,
            private_key_path=str(key_path),
            created_by_id=current_user.id
        )
        
        db.session.add(db_cert)
        db.session.commit()
        
        # Log event
        AuditLog.log_event(
            'certificate_created', 'pki', 'create', 'success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='certificate',
            resource_id=db_cert.serial_number,
            details={'common_name': data['common_name'], 'type': data.get('type', 'server')}
        )
        
        return jsonify({
            'success': True,
            'certificate': {
                'id': db_cert.id,
                'serial_number': db_cert.serial_number,
                'common_name': db_cert.common_name,
                'not_after': db_cert.not_after.isoformat(),
                'certificate_pem': cert_pem
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        AuditLog.log_event(
            'certificate_created', 'pki', 'create', 'failure',
            user=current_user,
            ip_address=request.remote_addr,
            details={'error': str(e)}
        )
        return jsonify({'error': str(e)}), 500

@api_bp.route('/certificates/<int:cert_id>', methods=['GET'])
@api_key_required
def get_certificate(cert_id):
    """Get certificate details"""
    cert = Certificate.query.get_or_404(cert_id)
    
    return jsonify({
        'id': cert.id,
        'serial_number': cert.serial_number,
        'common_name': cert.common_name,
        'subject': cert.subject,
        'issuer': cert.issuer,
        'type': cert.cert_type,
        'status': cert.status,
        'not_before': cert.not_before.isoformat(),
        'not_after': cert.not_after.isoformat(),
        'days_until_expiry': cert.days_until_expiry(),
        'certificate_pem': cert.certificate_pem,
        'created_at': cert.created_at.isoformat()
    })

@api_bp.route('/certificates/<int:cert_id>/revoke', methods=['POST'])
@api_key_required
def revoke_certificate(cert_id):
    """Revoke a certificate"""
    cert = Certificate.query.get_or_404(cert_id)
    
    if cert.status == 'revoked':
        return jsonify({'error': 'Certificate already revoked'}), 400
    
    data = request.get_json() or {}
    reason = data.get('reason', 'unspecified')
    
    cert.status = 'revoked'
    cert.revoked_at = datetime.utcnow()
    cert.revocation_reason = reason
    
    db.session.commit()
    
    AuditLog.log_event(
        'certificate_revoked', 'pki', 'revoke', 'success',
        user=current_user,
        ip_address=request.remote_addr,
        resource_type='certificate',
        resource_id=cert.serial_number,
        details={'reason': reason}
    )
    
    return jsonify({'success': True, 'message': 'Certificate revoked'})

# ============= Key Management APIs =============

@api_bp.route('/keys', methods=['GET'])
@api_key_required
def list_keys():
    """List all keys"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    query = Key.query
    
    # Filters
    status = request.args.get('status')
    if status:
        query = query.filter_by(status=status)
    
    keys = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'keys': [{
            'id': k.id,
            'key_id': k.key_id,
            'name': k.name,
            'type': k.key_type,
            'algorithm': k.algorithm,
            'purpose': k.purpose,
            'status': k.status,
            'version': k.version,
            'created_at': k.created_at.isoformat(),
            'days_until_rotation': k.days_until_rotation()
        } for k in keys.items],
        'total': keys.total,
        'pages': keys.pages,
        'current_page': keys.page
    })

@api_bp.route('/keys', methods=['POST'])
@api_key_required
def create_key():
    """Create a new key"""
    data = request.get_json()
    
    if not data.get('name'):
        return jsonify({'error': 'name is required'}), 400
    
    try:
        config = current_app.config['PKI_CONFIG']
        kms = KeyManagementSystem(config, config['storage']['keys_path'])
        
        key_type = data.get('type', 'symmetric')
        algorithm = data.get('algorithm', 'AES-256')
        purpose = data.get('purpose', 'encryption')
        
        # Generate key
        if key_type == 'symmetric':
            key_data = kms.generate_symmetric_key(algorithm, purpose)
        else:
            key_data = kms.generate_asymmetric_key(algorithm, purpose)
        
        # Create key ID
        key_id = secrets.token_urlsafe(32)
        
        # Set rotation policy
        rotation_days = data.get('rotation_policy_days', 
                                config['kms']['rotation']['default_policy_days'])
        next_rotation = datetime.utcnow() + timedelta(days=rotation_days) if rotation_days else None
        
        # Save to database
        db_key = Key(
            key_id=key_id,
            name=data['name'],
            description=data.get('description'),
            key_type=key_type,
            algorithm=algorithm,
            key_size=key_data.get('key_size'),
            purpose=purpose,
            status='active',
            encrypted_key_material=key_data['key_material'],
            version=1,
            rotation_policy_days=rotation_days,
            next_rotation_at=next_rotation,
            created_by_id=current_user.id
        )
        
        db.session.add(db_key)
        db.session.commit()
        
        AuditLog.log_event(
            'key_created', 'kms', 'create', 'success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='key',
            resource_id=key_id,
            details={'name': data['name'], 'algorithm': algorithm}
        )
        
        return jsonify({
            'success': True,
            'key': {
                'id': db_key.id,
                'key_id': key_id,
                'name': db_key.name,
                'algorithm': algorithm,
                'purpose': purpose,
                'created_at': db_key.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/keys/<int:key_id>', methods=['GET'])
@api_key_required
def get_key(key_id):
    """Get key details (not the actual key material)"""
    key = Key.query.get_or_404(key_id)
    
    return jsonify({
        'id': key.id,
        'key_id': key.key_id,
        'name': key.name,
        'description': key.description,
        'type': key.key_type,
        'algorithm': key.algorithm,
        'purpose': key.purpose,
        'status': key.status,
        'version': key.version,
        'rotation_policy_days': key.rotation_policy_days,
        'next_rotation_at': key.next_rotation_at.isoformat() if key.next_rotation_at else None,
        'created_at': key.created_at.isoformat(),
        'accessed_count': key.accessed_count
    })

@api_bp.route('/keys/<int:key_id>/encrypt', methods=['POST'])
@api_key_required
def encrypt_with_key(key_id):
    """Encrypt data with a key"""
    key = Key.query.get_or_404(key_id)
    
    if key.status != 'active':
        return jsonify({'error': 'Key is not active'}), 400
    
    data = request.get_json()
    if not data.get('plaintext'):
        return jsonify({'error': 'plaintext is required'}), 400
    
    try:
        config = current_app.config['PKI_CONFIG']
        kms = KeyManagementSystem(config, config['storage']['keys_path'])
        
        encrypted = kms.encrypt_data(
            key.key_id,
            data['plaintext'],
            key.encrypted_key_material
        )
        
        # Update access count
        key.accessed_count += 1
        key.last_accessed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/keys/<int:key_id>/decrypt', methods=['POST'])
@api_key_required
def decrypt_with_key(key_id):
    """Decrypt data with a key"""
    key = Key.query.get_or_404(key_id)
    
    data = request.get_json()
    if not data.get('encrypted_data'):
        return jsonify({'error': 'encrypted_data is required'}), 400
    
    try:
        config = current_app.config['PKI_CONFIG']
        kms = KeyManagementSystem(config, config['storage']['keys_path'])
        
        plaintext = kms.decrypt_data(
            data['encrypted_data'],
            key.encrypted_key_material
        )
        
        # Update access count
        key.accessed_count += 1
        key.last_accessed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'plaintext': plaintext.decode('utf-8')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= System APIs =============

@api_bp.route('/stats', methods=['GET'])
@api_key_required
def get_stats():
    """Get system statistics"""
    stats = {
        'certificates': {
            'total': Certificate.query.count(),
            'active': Certificate.query.filter_by(status='active').count(),
            'revoked': Certificate.query.filter_by(status='revoked').count(),
            'expired': Certificate.query.filter(
                Certificate.not_after < datetime.utcnow()
            ).count(),
            'expiring_soon': Certificate.query.filter(
                Certificate.not_after <= datetime.utcnow() + timedelta(days=30),
                Certificate.status == 'active'
            ).count()
        },
        'keys': {
            'total': Key.query.count(),
            'active': Key.query.filter_by(status='active').count(),
            'rotation_due': Key.query.filter(
                Key.next_rotation_at <= datetime.utcnow(),
                Key.status == 'active'
            ).count()
        },
        'users': {
            'total': User.query.count(),
            'active': User.query.filter_by(is_active=True).count()
        }
    }
    
    return jsonify(stats)

# ============= User Management APIs =============

@api_bp.route('/users', methods=['GET'])
@api_key_required
def list_users():
    """List all users (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    
    users = User.query.all()
    return jsonify({
        'success': True,
        'users': [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'is_active': u.is_active,
            'created_at': u.created_at.isoformat() if u.created_at else None,
            'last_login': u.last_login.isoformat() if u.last_login else None
        } for u in users]
    })

@api_bp.route('/users/<int:user_id>', methods=['GET'])
@api_key_required
def get_user(user_id):
    """Get user details"""
    if not current_user.is_admin() and current_user.id != user_id:
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
    })

@api_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@api_key_required
def toggle_user_status(user_id):
    """Toggle user active status (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot disable your own account'}), 400
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    AuditLog.log_event(
        'user_status_toggle', 'user', 'update', 'success',
        user=current_user, ip_address=request.remote_addr,
        details={'target_user': user.username, 'new_status': user.is_active}
    )
    
    return jsonify({
        'success': True,
        'message': f'User {"activated" if user.is_active else "deactivated"}',
        'is_active': user.is_active
    })

@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@api_key_required
def delete_user(user_id):
    """Delete user (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    user = User.query.get_or_404(user_id)
    username = user.username
    
    db.session.delete(user)
    db.session.commit()
    
    AuditLog.log_event(
        'user_delete', 'user', 'delete', 'success',
        user=current_user, ip_address=request.remote_addr,
        details={'deleted_user': username}
    )
    
    return jsonify({
        'success': True,
        'message': f'User {username} deleted successfully'
    })

# ============= Audit Log APIs =============

@api_bp.route('/audit/<int:log_id>', methods=['GET'])
@api_key_required
def get_audit_log(log_id):
    """Get audit log details"""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    
    log = AuditLog.query.get_or_404(log_id)
    return jsonify({
        'success': True,
        'log': {
            'id': log.id,
            'event_type': log.event_type,
            'event_category': log.event_category,
            'event_action': log.event_action,
            'event_status': log.event_status,
            'user': log.user.username if log.user else None,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat(),
            'details': log.details
        }
    })

@api_bp.route('/audit', methods=['GET'])
@api_key_required
def list_audit_logs():
    """List audit logs (Admin only)"""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin privileges required'}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    query = AuditLog.query
    
    # Filters
    category = request.args.get('category')
    if category:
        query = query.filter_by(event_category=category)
    
    action = request.args.get('action')
    if action:
        query = query.filter_by(action=action)
    
    status = request.args.get('status')
    if status:
        query = query.filter_by(status=status)
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'success': True,
        'logs': [{
            'id': log.id,
            'event_type': log.event_type,
            'category': log.event_category,
            'action': log.action,
            'status': log.status,
            'user_id': log.user_id,
            'username': log.user.username if log.user else None,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat(),
            'resource_type': log.resource_type,
            'resource_id': log.resource_id
        } for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': logs.page
    })

@api_bp.route('/', methods=['GET'])
@api_bp.route('/docs')
def api_docs():
    """API Documentation"""
    return jsonify({
        'version': '1.0',
        'endpoints': {
            'certificates': {
                'GET /api/v1/certificates': 'List all certificates',
                'POST /api/v1/certificates': 'Create a new certificate',
                'GET /api/v1/certificates/<id>': 'Get certificate details',
                'POST /api/v1/certificates/<id>/revoke': 'Revoke a certificate'
            },
            'keys': {
                'GET /api/v1/keys': 'List all keys',
                'POST /api/v1/keys': 'Create a new key',
                'GET /api/v1/keys/<id>': 'Get key details',
                'POST /api/v1/keys/<id>/encrypt': 'Encrypt data with key',
                'POST /api/v1/keys/<id>/decrypt': 'Decrypt data with key'
            },
            'users': {
                'GET /api/v1/users': 'List all users (Admin)',
                'GET /api/v1/users/<id>': 'Get user details',
                'POST /api/v1/users/<id>/toggle': 'Toggle user status (Admin)',
                'DELETE /api/v1/users/<id>': 'Delete user (Admin)'
            },
            'audit': {
                'GET /api/v1/audit': 'List all audit logs (Admin)',
                'GET /api/v1/audit/<id>': 'Get audit log details (Admin)'
            },
            'system': {
                'GET /api/v1/stats': 'Get system statistics'
            }
        }
    })
