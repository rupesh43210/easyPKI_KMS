"""
Web interface routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Certificate, Key, AuditLog
from datetime import datetime, timedelta
from sqlalchemy import func, desc
from pathlib import Path
import io

web_bp = Blueprint('web', __name__)

@web_bp.route('/')
@login_required
def index():
    """Dashboard"""
    # Get statistics - only count active items
    active_certs = Certificate.query.filter_by(status='active').count()
    expiring_soon = Certificate.query.filter(
        Certificate.not_after <= datetime.utcnow() + timedelta(days=30),
        Certificate.status == 'active'
    ).count()
    
    active_keys = Key.query.filter_by(status='active').count()
    
    # Recent activity - only show active items
    recent_certs = Certificate.query.filter_by(status='active').order_by(desc(Certificate.created_at)).limit(5).all()
    recent_keys = Key.query.filter_by(status='active').order_by(desc(Key.created_at)).limit(5).all()
    recent_audit = AuditLog.query.order_by(desc(AuditLog.timestamp)).limit(10).all()
    
    return render_template('dashboard.html',
                         active_certs=active_certs,
                         expiring_soon=expiring_soon,
                         active_keys=active_keys,
                         recent_certs=recent_certs,
                         recent_keys=recent_keys,
                         recent_audit=recent_audit)

@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            AuditLog.log_event(
                'user_login', 'auth', 'login', 'success',
                user=user, ip_address=request.remote_addr
            )
            
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('web.index'))
        else:
            AuditLog.log_event(
                'user_login', 'auth', 'login', 'failure',
                ip_address=request.remote_addr,
                details={'username': username, 'reason': 'invalid_credentials'}
            )
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@web_bp.route('/logout')
@login_required
def logout():
    """Logout"""
    AuditLog.log_event(
        'user_logout', 'auth', 'logout', 'success',
        user=current_user, ip_address=request.remote_addr
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('web.login'))

@web_bp.route('/certificates')
@login_required
def certificates():
    """List certificates"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query = Certificate.query
    
    # Filters
    status = request.args.get('status')
    if status and status != 'all':
        query = query.filter_by(status=status)
    elif not status:
        # By default, only show active certificates (hide revoked/expired)
        query = query.filter_by(status='active')
    
    cert_type = request.args.get('type')
    if cert_type:
        query = query.filter_by(cert_type=cert_type)
    
    search = request.args.get('search')
    if search:
        query = query.filter(
            (Certificate.common_name.ilike(f'%{search}%')) |
            (Certificate.serial_number.ilike(f'%{search}%'))
        )
    
    certs = query.order_by(desc(Certificate.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('certificates.html', certificates=certs)

@web_bp.route('/certificates/sign-csr', methods=['GET', 'POST'])
@login_required
def sign_csr():
    """Sign a Certificate Signing Request"""
    if request.method == 'POST':
        try:
            from app.pki.ca import CertificateAuthority
            from cryptography.hazmat.primitives import serialization
            from pathlib import Path
            import yaml
            
            # Get form data
            csr_pem = request.form.get('csr_pem')
            cert_type = request.form.get('cert_type', 'server')
            validity_days = int(request.form.get('validity_days', 365))
            
            # Optional SAN
            san_list_raw = request.form.get('san_list', '')
            san_list = [s.strip() for s in san_list_raw.split(',') if s.strip()] if san_list_raw else None
            
            # Validate
            if not csr_pem:
                flash('CSR PEM is required', 'error')
                return redirect(url_for('web.sign_csr'))
            
            # Load config
            with open('config/config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            
            storage_path = Path(config['storage']['base_path'])
            
            # Initialize CA
            ca = CertificateAuthority(config, storage_path)
            
            # Sign CSR
            cert = ca.sign_csr(csr_pem, cert_type, validity_days, san_list)
            
            # Get certificate details
            serial_number = format(cert.serial_number, 'x')
            common_name = cert.subject.get_attributes_for_oid(cert.subject._attributes[0].oid)[0].value
            
            # Save certificate to database
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            new_cert = Certificate(
                serial_number=serial_number,
                common_name=common_name,
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                cert_type=cert_type,
                key_algorithm='RSA',  # Detect from CSR
                key_size=cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 0,
                hash_algorithm='SHA256',
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
                status='active',
                certificate_pem=cert_pem,
                private_key_path=None,  # CSR signing doesn't include private key
                created_by_id=current_user.id
            )
            
            db.session.add(new_cert)
            db.session.commit()
            
            # Save certificate file
            cert_path = storage_path / 'certs' / f'{serial_number}.crt'
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Audit log
            AuditLog.log_event(
                'certificate_sign_csr', 'pki', 'create', 'success',
                user=current_user, ip_address=request.remote_addr,
                resource_type='certificate', resource_id=serial_number,
                details={'common_name': common_name, 'type': cert_type}
            )
            
            flash(f'CSR signed successfully! Serial: {serial_number}', 'success')
            return redirect(url_for('web.certificate_detail', cert_id=new_cert.id))
            
        except Exception as e:
            db.session.rollback()
            AuditLog.log_event(
                'certificate_sign_csr', 'pki', 'create', 'failure',
                user=current_user, ip_address=request.remote_addr,
                details={'error': str(e)}
            )
            flash(f'Error signing CSR: {str(e)}', 'error')
            return redirect(url_for('web.sign_csr'))
    
    return render_template('sign_csr.html')

@web_bp.route('/certificates/create', methods=['GET', 'POST'])
@login_required
def create_certificate():
    """Create certificate"""
    if request.method == 'POST':
        try:
            from app.pki.ca import CertificateAuthority
            from cryptography.hazmat.primitives import serialization
            from pathlib import Path
            
            # Get form data
            common_name = request.form.get('common_name')
            cert_type = request.form.get('cert_type')
            validity_days = int(request.form.get('validity_days', 365))
            key_size = int(request.form.get('key_size', 4096))
            
            # Optional fields
            san_list_raw = request.form.get('san_list', '')
            san_list = [s.strip() for s in san_list_raw.split('\n') if s.strip()] if san_list_raw else None
            
            organization = request.form.get('organization')
            organizational_unit = request.form.get('organizational_unit')
            country = request.form.get('country')
            state = request.form.get('state')
            locality = request.form.get('locality')
            email = request.form.get('email')
            
            # Validate required fields
            if not common_name or not cert_type:
                flash('Common Name and Certificate Type are required', 'error')
                return redirect(url_for('web.create_certificate'))
            
            # Initialize CA
            config = current_user.__dict__.get('_sa_instance_state')
            from flask import current_app
            config = current_app.config['PKI_CONFIG']
            ca = CertificateAuthority(config, config['storage']['ca_path'])
            
            # Create certificate
            # Note: create_certificate only supports common_name, cert_type, validity_days, 
            # key_size, san_list, and organization parameters
            private_key, cert = ca.create_certificate(
                common_name=common_name,
                cert_type=cert_type,
                validity_days=validity_days,
                key_size=key_size,
                san_list=san_list,
                organization=organization
            )
            
            # Save to database
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            
            # Save files
            cert_path = Path(config['storage']['certs_path']) / f"{cert.serial_number:x}.crt"
            key_path = Path(config['storage']['certs_path']) / f"{cert.serial_number:x}.key"
            ca._save_certificate_and_key(cert, private_key, cert_path, key_path)
            
            # Create database record
            from cryptography import x509
            db_cert = Certificate(
                serial_number=f"{cert.serial_number:x}",
                common_name=common_name,
                subject=cert.subject.rfc4514_string(),  # Fixed: added subject field
                cert_type=cert_type,
                status='active',
                issuer=cert.issuer.rfc4514_string(),
                not_before=cert.not_valid_before,  # Fixed: use not_valid_before
                not_after=cert.not_valid_after,    # Fixed: use not_valid_after
                key_size=key_size,
                hash_algorithm='SHA256',  # Fixed: use hash_algorithm instead of signature_algorithm
                certificate_pem=cert_pem,
                private_key_path=str(key_path),  # Store private key path
                created_by_id=current_user.id
            )
            
            db.session.add(db_cert)
            db.session.commit()
            
            # Log audit
            AuditLog.log_event(
                'certificate_created', 'pki', 'create', 'success',
                user=current_user,
                ip_address=request.remote_addr,
                resource_type='certificate',
                resource_id=db_cert.serial_number,
                details={'common_name': common_name, 'type': cert_type}
            )
            
            flash(f'Certificate "{common_name}" created successfully! Serial: {db_cert.serial_number}', 'success')
            return redirect(url_for('web.certificates'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating certificate: {str(e)}', 'error')
            return redirect(url_for('web.create_certificate'))
    
    return render_template('create_certificate.html')

@web_bp.route('/certificates/<int:cert_id>')
@login_required
def certificate_detail(cert_id):
    """Certificate details"""
    cert = Certificate.query.get_or_404(cert_id)
    return render_template('certificate_detail.html', certificate=cert)

@web_bp.route('/certificates/<int:cert_id>/download-key')
@login_required
def download_private_key(cert_id):
    """Download private key for certificate"""
    try:
        cert = Certificate.query.get_or_404(cert_id)
        
        # Check if user has permission (admin or creator)
        if not current_user.is_admin() and cert.created_by_id != current_user.id:
            flash('You do not have permission to download this private key', 'error')
            return redirect(url_for('web.certificate_detail', cert_id=cert_id))
        
        # Try to find the private key file
        config = current_app.config['PKI_CONFIG']
        key_path = None
        
        # Strategy 1: Try the stored private_key_path (check if it's relative or absolute)
        if cert.private_key_path:
            potential_path = Path(cert.private_key_path)
            # If path is not absolute, it might be relative to project root
            if not potential_path.is_absolute():
                potential_path = Path.cwd() / potential_path
            if potential_path.exists():
                key_path = potential_path
        
        # Strategy 2: Try serial number in certs_path (from current directory)
        if not key_path:
            potential_path = Path.cwd() / config['storage']['certs_path'] / f"{cert.serial_number}.key"
            if potential_path.exists():
                key_path = potential_path
        
        # Strategy 3: Try with just config path (might be absolute)
        if not key_path:
            potential_path = Path(config['storage']['certs_path']) / f"{cert.serial_number}.key"
            if potential_path.exists():
                key_path = potential_path
        
        # Strategy 4: Try keys_path
        if not key_path:
            potential_path = Path.cwd() / config['storage']['keys_path'] / f"{cert.serial_number}.key"
            if potential_path.exists():
                key_path = potential_path
        
        if not key_path:
            flash(f'Private key file not found. Serial: {cert.serial_number}. Please ensure the certificate was created with this system.', 'error')
            return redirect(url_for('web.certificate_detail', cert_id=cert_id))
        
        # Load and decrypt the private key (keys are encrypted with secret_key)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_password = config['app']['secret_key'].encode()
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=key_password,
                backend=default_backend()
            )
        
        # Serialize the private key without encryption (for user download)
        unencrypted_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Log audit
        AuditLog.log_event(
            'certificate_key_downloaded', 'pki', 'download', 'success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='certificate',
            resource_id=cert.serial_number,
            details={'common_name': cert.common_name}
        )
        
        # Send decrypted file
        return send_file(
            io.BytesIO(unencrypted_key_pem),
            as_attachment=True,
            download_name=f"{cert.serial_number}.key",
            mimetype='application/x-pem-file'
        )
        
    except Exception as e:
        flash(f'Error downloading private key: {str(e)}', 'error')
        return redirect(url_for('web.certificate_detail', cert_id=cert_id))

@web_bp.route('/certificates/<int:cert_id>/export-pkcs12')
@login_required
def export_pkcs12(cert_id):
    """Export certificate and private key as PKCS#12 bundle"""
    try:
        cert = Certificate.query.get_or_404(cert_id)
        
        # Check permissions: admin or creator only
        if current_user.role != 'admin' and cert.created_by_id != current_user.id:
            flash('You do not have permission to export this certificate', 'error')
            return redirect(url_for('web.certificate_detail', cert_id=cert_id))
        
        # Load certificate
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import pkcs12
        
        certificate = x509.load_pem_x509_certificate(
            cert.certificate_pem.encode(),
            default_backend()
        )
        
        # Find the private key file
        config = current_app.config['PKI_CONFIG']
        key_path = None
        
        # Try multiple locations to find the private key
        if cert.private_key_path:
            potential_path = Path(cert.private_key_path)
            if not potential_path.is_absolute():
                potential_path = Path.cwd() / potential_path
            if potential_path.exists():
                key_path = potential_path
        
        if not key_path:
            potential_path = Path.cwd() / config['storage']['certs_path'] / f"{cert.serial_number}.key"
            if potential_path.exists():
                key_path = potential_path
        
        if not key_path:
            potential_path = Path(config['storage']['certs_path']) / f"{cert.serial_number}.key"
            if potential_path.exists():
                key_path = potential_path
        
        if not key_path:
            flash('Private key file not found. Cannot export PKCS#12.', 'error')
            return redirect(url_for('web.certificate_detail', cert_id=cert_id))
        
        # Load private key (keys are encrypted with the app secret_key)
        key_password = config['app']['secret_key'].encode()
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=key_password,
                backend=default_backend()
            )
        
        # Create PKCS#12 bundle with a default password (user should change this)
        # Using common name as the friendly name
        p12_password = b'changeme'  # Default password
        
        p12_data = pkcs12.serialize_key_and_certificates(
            name=cert.common_name.encode('utf-8'),
            key=private_key,
            cert=certificate,
            cas=None,  # Could add CA chain here
            encryption_algorithm=serialization.BestAvailableEncryption(p12_password)
        )
        
        # Log the export
        AuditLog.log_event(
            event_type='pkcs12_exported',
            category='pki',
            action='export',
            status='success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='certificate',
            resource_id=cert.serial_number,
            details={
                'serial_number': cert.serial_number,
                'common_name': cert.common_name,
                'cert_id': cert.id
            }
        )
        
        # Flash message with password info
        flash('PKCS#12 file exported successfully! Default password is: changeme (Please change this!)', 'warning')
        
        # Return as downloadable file
        return send_file(
            io.BytesIO(p12_data),
            mimetype='application/x-pkcs12',
            as_attachment=True,
            download_name=f"{cert.common_name.replace(' ', '_')}.p12"
        )
        
    except Exception as e:
        flash(f'Error exporting PKCS#12: {str(e)}', 'error')
        return redirect(url_for('web.certificate_detail', cert_id=cert_id))

@web_bp.route('/keys')
@login_required
def keys():
    """List keys"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query = Key.query
    
    # Filters
    status = request.args.get('status')
    if status and status != 'all':
        query = query.filter_by(status=status)
    elif not status:
        # By default, only show active keys (hide disabled/revoked)
        query = query.filter_by(status='active')
    
    key_type = request.args.get('type')
    if key_type:
        query = query.filter_by(key_type=key_type)
    
    search = request.args.get('search')
    if search:
        query = query.filter(
            (Key.name.ilike(f'%{search}%')) |
            (Key.key_id.ilike(f'%{search}%'))
        )
    
    keys = query.order_by(desc(Key.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('keys.html', keys=keys)

@web_bp.route('/keys/create', methods=['GET', 'POST'])
@login_required
def create_key():
    """Create key"""
    if request.method == 'POST':
        try:
            from app.kms.kms import KeyManagementSystem
            from flask import current_app
            import secrets
            
            # Get form data
            key_name = request.form.get('key_name')
            key_type = request.form.get('key_type')
            algorithm = request.form.get('algorithm')
            purpose = request.form.get('purpose', 'encryption')
            rotation_days = request.form.get('rotation_days')
            description = request.form.get('description')
            
            # Validate required fields
            if not key_name or not key_type or not algorithm:
                flash('Key Name, Type, and Algorithm are required', 'error')
                return redirect(url_for('web.create_key'))
            
            # Initialize KMS
            config = current_app.config['PKI_CONFIG']
            kms = KeyManagementSystem(config, config['storage']['keys_path'])
            
            # Generate key
            if key_type == 'symmetric':
                key_data = kms.generate_symmetric_key(algorithm, purpose)
                encrypted_key_material = key_data['key_material']
            else:
                key_data = kms.generate_asymmetric_key(algorithm, purpose)
                encrypted_key_material = key_data['private_key_material']
            
            # Create key ID
            key_id = secrets.token_urlsafe(32)
            
            # Set rotation policy
            rotation_days_int = int(rotation_days) if rotation_days else config['kms']['rotation']['default_policy_days']
            next_rotation = datetime.utcnow() + timedelta(days=rotation_days_int) if rotation_days_int else None
            
            # Save to database
            db_key = Key(
                key_id=key_id,
                name=key_name,
                description=description,
                key_type=key_type,
                algorithm=algorithm,
                key_size=key_data.get('key_size'),
                purpose=purpose,
                status='active',
                encrypted_key_material=encrypted_key_material,
                version=1,
                rotation_policy_days=rotation_days_int,
                next_rotation_at=next_rotation,
                created_by_id=current_user.id
            )
            
            db.session.add(db_key)
            db.session.commit()
            
            # Log audit
            AuditLog.log_event(
                'key_created', 'kms', 'create', 'success',
                user=current_user,
                ip_address=request.remote_addr,
                resource_type='key',
                resource_id=key_id,
                details={'name': key_name, 'algorithm': algorithm, 'type': key_type}
            )
            
            flash(f'Encryption key "{key_name}" created successfully!', 'success')
            return redirect(url_for('web.keys'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating key: {str(e)}', 'error')
            return redirect(url_for('web.create_key'))
    
    return render_template('create_key.html')

@web_bp.route('/keys/<int:key_id>')
@login_required
def key_detail(key_id):
    """Key details"""
    key = Key.query.get_or_404(key_id)
    return render_template('key_detail.html', key=key)

@web_bp.route('/keys/<int:key_id>/rotate', methods=['POST'])
@login_required
def rotate_key(key_id):
    """Rotate encryption key"""
    try:
        from app.kms.kms import KeyManagementSystem
        from flask import current_app
        import secrets
        
        # Get the key
        key = Key.query.get_or_404(key_id)
        
        # Check if key is active
        if key.status != 'active':
            flash(f'Cannot rotate key with status: {key.status}', 'error')
            return redirect(url_for('web.key_detail', key_id=key_id))
        
        # Initialize KMS
        config = current_app.config['PKI_CONFIG']
        kms = KeyManagementSystem(config, config['storage']['keys_path'])
        
        # Generate new key with same parameters
        if key.key_type == 'symmetric':
            key_data = kms.generate_symmetric_key(key.algorithm, key.purpose)
            encrypted_key_material = key_data['key_material']
        else:
            key_data = kms.generate_asymmetric_key(key.algorithm, key.purpose)
            encrypted_key_material = key_data['private_key_material']
        
        # Mark old key as rotated
        key.status = 'rotated'
        key.last_rotated_at = datetime.utcnow()
        
        # Create new key version
        new_key = Key(
            key_id=secrets.token_urlsafe(32),
            name=f"{key.name} (v{key.version + 1})",
            description=f"Rotated from key ID: {key.key_id}",
            key_type=key.key_type,
            algorithm=key.algorithm,
            key_size=key.key_size,
            purpose=key.purpose,
            status='active',
            encrypted_key_material=encrypted_key_material,
            version=key.version + 1,
            rotation_policy_days=key.rotation_policy_days,
            next_rotation_at=datetime.utcnow() + timedelta(days=key.rotation_policy_days) if key.rotation_policy_days else None,
            created_by_id=current_user.id
        )
        
        db.session.add(new_key)
        db.session.commit()
        
        # Log audit
        AuditLog.log_event(
            'key_rotated', 'kms', 'rotate', 'success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='key',
            resource_id=key.key_id,
            details={
                'old_key_id': key.key_id,
                'new_key_id': new_key.key_id,
                'version': new_key.version,
                'algorithm': key.algorithm
            }
        )
        
        flash(f'Key rotated successfully! New key version: {new_key.version}', 'success')
        return redirect(url_for('web.key_detail', key_id=new_key.id))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rotating key: {str(e)}', 'error')
        return redirect(url_for('web.key_detail', key_id=key_id))

@web_bp.route('/keys/<int:key_id>/export-key')
@login_required
def export_key_material(key_id):
    """Export key material for encryption keys (both symmetric and asymmetric)"""
    try:
        key = Key.query.get_or_404(key_id)
        
        # Check permissions: admin or creator only
        if current_user.role != 'admin' and key.created_by_id != current_user.id:
            flash('You do not have permission to export this key', 'error')
            return redirect(url_for('web.key_detail', key_id=key_id))
        
        # Get the KMS to decrypt the key
        config = current_app.config['PKI_CONFIG']
        from app.kms.kms import KeyManagementSystem
        kms = KeyManagementSystem(config, config['storage']['keys_path'])
        
        # Decrypt the key material
        import base64
        decrypted_material = kms._decrypt_key_material(key.encrypted_key_material)
        
        if key.key_type == 'symmetric':
            # Symmetric key: export as base64-encoded raw bytes
            key_b64 = base64.b64encode(decrypted_material).decode('utf-8')
            
            # Create a text file with key information
            key_content = f"""# Symmetric Encryption Key
# Name: {key.name}
# Algorithm: {key.algorithm}
# Key ID: {key.key_id}
# Created: {key.created_at.isoformat()}
# 
# WARNING: Keep this key secure! Anyone with this key can decrypt your data.
#
# Key Material (Base64):
{key_b64}

# To use this key in Python:
# import base64
# key_bytes = base64.b64decode('{key_b64}')
#
# For AES encryption with this key:
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce), backend=default_backend())
"""
            
            file_content = key_content.encode('utf-8')
            mimetype = 'text/plain'
            filename = f"{key.name.replace(' ', '_')}_symmetric.key"
            
        else:  # asymmetric
            # Asymmetric key: export as PEM format
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            private_key = serialization.load_pem_private_key(
                decrypted_material,
                password=None,
                backend=default_backend()
            )
            
            # Serialize private key to PEM format
            file_content = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            mimetype = 'application/x-pem-file'
            filename = f"{key.name.replace(' ', '_')}_private.key"
        
        # Log the export
        AuditLog.log_event(
            event_type='key_material_exported',
            category='kms',
            action='export',
            status='success',
            user=current_user,
            ip_address=request.remote_addr,
            resource_type='key',
            resource_id=key.key_id,
            details={
                'key_id': key.key_id, 
                'key_name': key.name, 
                'key_type': key.key_type,
                'algorithm': key.algorithm,
                'db_id': key.id
            }
        )
        
        # Return as downloadable file
        return send_file(
            io.BytesIO(file_content),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        flash(f'Error exporting key: {str(e)}', 'error')
        return redirect(url_for('web.key_detail', key_id=key_id))

@web_bp.route('/audit')
@login_required
def audit():
    """Audit logs"""
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('web.index'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    query = AuditLog.query
    
    # Filters
    category = request.args.get('category')
    if category:
        query = query.filter_by(event_category=category)
    
    action = request.args.get('action')
    if action:
        query = query.filter_by(event_action=action)
    
    status = request.args.get('status')
    if status:
        query = query.filter_by(event_status=status)
    
    user_filter = request.args.get('user')
    if user_filter:
        query = query.join(User).filter(User.username.ilike(f'%{user_filter}%'))
    
    logs = query.order_by(desc(AuditLog.timestamp)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit.html', logs=logs)

@web_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page"""
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('web.index'))
    
    if request.method == 'POST':
        settings_type = request.form.get('settings_type')
        
        if settings_type == 'pki':
            # Save PKI settings
            from app.models import SystemSetting
            
            cert_validity = request.form.get('cert_validity', type=int)
            key_size = request.form.get('key_size', type=int)
            organization = request.form.get('organization', '')
            
            SystemSetting.set_setting('pki', 'default_cert_validity', cert_validity, 'integer', 
                                     'Default certificate validity in days', current_user)
            SystemSetting.set_setting('pki', 'default_key_size', key_size, 'integer',
                                     'Default key size in bits', current_user)
            SystemSetting.set_setting('pki', 'organization', organization, 'string',
                                     'Certificate organization name', current_user)
            
            AuditLog.log_event(
                'settings_update', 'system', 'update', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'type': 'pki', 'cert_validity': cert_validity, 'key_size': key_size}
            )
            flash('PKI settings saved successfully!', 'success')
            
        elif settings_type == 'kms':
            # Save KMS settings
            from app.models import SystemSetting
            
            rotation_days = request.form.get('rotation_days', type=int)
            algorithm = request.form.get('algorithm', '')
            auto_rotation = request.form.get('auto_rotation') == 'on'
            
            SystemSetting.set_setting('kms', 'default_rotation_days', rotation_days, 'integer',
                                     'Default key rotation period in days', current_user)
            SystemSetting.set_setting('kms', 'default_algorithm', algorithm, 'string',
                                     'Default encryption algorithm', current_user)
            SystemSetting.set_setting('kms', 'auto_rotation_enabled', auto_rotation, 'boolean',
                                     'Enable automatic key rotation', current_user)
            
            AuditLog.log_event(
                'settings_update', 'system', 'update', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'type': 'kms', 'rotation_days': rotation_days, 'algorithm': algorithm}
            )
            flash('KMS settings saved successfully!', 'success')
            
        elif settings_type == 'security':
            # Save Security settings
            from app.models import SystemSetting
            
            session_timeout = request.form.get('session_timeout', type=int)
            password_policy = request.form.get('password_policy', '')
            require_2fa = request.form.get('require_2fa') == 'on'
            audit_all = request.form.get('audit_all') == 'on'
            
            SystemSetting.set_setting('security', 'session_timeout', session_timeout, 'integer',
                                     'Session timeout in minutes', current_user)
            SystemSetting.set_setting('security', 'password_policy', password_policy, 'string',
                                     'Password policy level', current_user)
            SystemSetting.set_setting('security', 'require_2fa', require_2fa, 'boolean',
                                     'Require two-factor authentication', current_user)
            SystemSetting.set_setting('security', 'audit_all_actions', audit_all, 'boolean',
                                     'Log all user actions', current_user)
            
            AuditLog.log_event(
                'settings_update', 'system', 'update', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'type': 'security', 'session_timeout': session_timeout}
            )
            flash('Security settings saved successfully!', 'success')
        
        return redirect(url_for('web.settings'))
    
    # Load current settings
    from app.models import SystemSetting
    
    pki_settings = SystemSetting.get_all_by_category('pki')
    kms_settings = SystemSetting.get_all_by_category('kms')
    security_settings = SystemSetting.get_all_by_category('security')
    
    return render_template('settings.html',
                          pki_settings=pki_settings,
                          kms_settings=kms_settings,
                          security_settings=security_settings)

@web_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile"""
    if request.method == 'POST':
        current_user.email = request.form.get('email')
        current_user.full_name = request.form.get('full_name')
        db.session.commit()
        
        AuditLog.log_event(
            'user_profile_update', 'user', 'update', 'success',
            user=current_user, ip_address=request.remote_addr
        )
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('web.profile'))
    
    return render_template('profile.html')

@web_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('web.change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('web.change_password'))
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('web.change_password'))
        
        current_user.set_password(new_password)
        db.session.commit()
        
        AuditLog.log_event(
            'user_password_change', 'user', 'update', 'success',
            user=current_user, ip_address=request.remote_addr
        )
        flash('Password changed successfully!', 'success')
        return redirect(url_for('web.profile'))
    
    return render_template('change_password.html')

@web_bp.route('/users')
@login_required
def users():
    """User management"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('web.index'))
    
    all_users = User.query.order_by(User.username).all()
    return render_template('users.html', users=all_users)

@web_bp.route('/users/create', methods=['POST'])
@login_required
def create_user():
    """Create new user"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('web.index'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    full_name = request.form.get('full_name')
    password = request.form.get('password')
    role = request.form.get('role')
    
    # Validate
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('web.users'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already exists', 'error')
        return redirect(url_for('web.users'))
    
    # Create user
    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        is_active=True
    )
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    AuditLog.log_event(
        'user_create', 'user', 'create', 'success',
        user=current_user, ip_address=request.remote_addr,
        details={'new_user': username, 'role': role}
    )
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('web.users'))

@web_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_user(user_id):
    """Edit user"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('web.index'))
    
    user = User.query.get_or_404(user_id)
    
    user.email = request.form.get('email')
    user.full_name = request.form.get('full_name')
    user.role = request.form.get('role')
    
    db.session.commit()
    
    AuditLog.log_event(
        'user_update', 'user', 'update', 'success',
        user=current_user, ip_address=request.remote_addr,
        details={'target_user': user.username, 'role': user.role}
    )
    flash(f'User {user.username} updated successfully!', 'success')
    return redirect(url_for('web.users'))

@web_bp.route('/system/reset', methods=['POST'])
@login_required
def reset_system():
    """Reset system to factory defaults"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('web.index'))
    
    # Verify confirmation code
    confirmation_code = request.form.get('confirmation_code')
    reset_type = request.form.get('reset_type')
    
    if confirmation_code != 'RESET':
        flash('Invalid confirmation code. Type "RESET" to confirm.', 'error')
        return redirect(url_for('web.settings'))
    
    try:
        if reset_type == 'settings':
            # Reset only settings to defaults
            from app.models import SystemSetting
            
            # Delete all current settings
            SystemSetting.query.delete()
            
            # Reinitialize defaults
            SystemSetting.set_setting('pki', 'default_cert_validity', 365, 'integer', 
                                     'Default certificate validity in days')
            SystemSetting.set_setting('pki', 'default_key_size', 2048, 'integer',
                                     'Default key size in bits')
            SystemSetting.set_setting('pki', 'organization', 'Your Organization', 'string',
                                     'Certificate organization name')
            
            SystemSetting.set_setting('kms', 'default_rotation_days', 90, 'integer',
                                     'Default key rotation period in days')
            SystemSetting.set_setting('kms', 'default_algorithm', 'AES-256', 'string',
                                     'Default encryption algorithm')
            SystemSetting.set_setting('kms', 'auto_rotation_enabled', True, 'boolean',
                                     'Enable automatic key rotation')
            
            SystemSetting.set_setting('security', 'session_timeout', 30, 'integer',
                                     'Session timeout in minutes')
            SystemSetting.set_setting('security', 'password_policy', 'standard', 'string',
                                     'Password policy level')
            SystemSetting.set_setting('security', 'require_2fa', False, 'boolean',
                                     'Require two-factor authentication')
            SystemSetting.set_setting('security', 'audit_all_actions', True, 'boolean',
                                     'Log all user actions')
            
            AuditLog.log_event(
                'system_reset_settings', 'system', 'reset', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'reset_type': 'settings'}
            )
            flash('System settings reset to factory defaults successfully!', 'success')
            
        elif reset_type == 'all':
            # Full system reset (DANGEROUS!)
            from app.models import SystemSetting
            
            # Keep admin user, delete all others
            User.query.filter(User.id != current_user.id).delete()
            
            # Mark all certificates as revoked (don't delete, for audit trail)
            Certificate.query.update({'status': 'revoked', 'revoked_at': datetime.utcnow()})
            
            # Disable all keys (don't delete, for audit trail)
            Key.query.update({'status': 'disabled'})
            
            # Reset settings
            SystemSetting.query.delete()
            
            # Reinitialize default settings
            SystemSetting.set_setting('pki', 'default_cert_validity', 365, 'integer')
            SystemSetting.set_setting('pki', 'default_key_size', 2048, 'integer')
            SystemSetting.set_setting('pki', 'organization', 'Your Organization', 'string')
            SystemSetting.set_setting('kms', 'default_rotation_days', 90, 'integer')
            SystemSetting.set_setting('kms', 'default_algorithm', 'AES-256', 'string')
            SystemSetting.set_setting('kms', 'auto_rotation_enabled', True, 'boolean')
            SystemSetting.set_setting('security', 'session_timeout', 30, 'integer')
            SystemSetting.set_setting('security', 'password_policy', 'standard', 'string')
            SystemSetting.set_setting('security', 'require_2fa', False, 'boolean')
            SystemSetting.set_setting('security', 'audit_all_actions', True, 'boolean')
            
            db.session.commit()
            
            AuditLog.log_event(
                'system_reset_all', 'system', 'reset', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'reset_type': 'all', 'warning': 'Full system reset performed'}
            )
            flash('SYSTEM RESET COMPLETE! All data has been reset to factory defaults.', 'warning')
            
        elif reset_type == 'complete':
            # Complete reset including audit logs (NUCLEAR!)
            from app.models import SystemSetting
            
            # Log this action BEFORE deleting audit logs
            AuditLog.log_event(
                'system_reset_complete', 'system', 'reset', 'success',
                user=current_user, ip_address=request.remote_addr,
                details={'reset_type': 'complete', 'warning': 'COMPLETE SYSTEM RESET - ALL AUDIT LOGS WILL BE DELETED'}
            )
            db.session.commit()
            
            # Keep admin user, delete all others
            User.query.filter(User.id != current_user.id).delete()
            
            # Mark all certificates as revoked
            Certificate.query.update({'status': 'revoked', 'revoked_at': datetime.utcnow()})
            
            # Disable all keys
            Key.query.update({'status': 'disabled'})
            
            # DELETE ALL AUDIT LOGS (DANGEROUS!)
            AuditLog.query.delete()
            
            # Reset settings
            SystemSetting.query.delete()
            
            # Reinitialize default settings
            SystemSetting.set_setting('pki', 'default_cert_validity', 365, 'integer')
            SystemSetting.set_setting('pki', 'default_key_size', 2048, 'integer')
            SystemSetting.set_setting('pki', 'organization', 'Your Organization', 'string')
            SystemSetting.set_setting('kms', 'default_rotation_days', 90, 'integer')
            SystemSetting.set_setting('kms', 'default_algorithm', 'AES-256', 'string')
            SystemSetting.set_setting('kms', 'auto_rotation_enabled', True, 'boolean')
            SystemSetting.set_setting('security', 'session_timeout', 30, 'integer')
            SystemSetting.set_setting('security', 'password_policy', 'standard', 'string')
            SystemSetting.set_setting('security', 'require_2fa', False, 'boolean')
            SystemSetting.set_setting('security', 'audit_all_actions', True, 'boolean')
            
            db.session.commit()
            
            flash('COMPLETE RESET FINISHED! All data and audit logs have been cleared.', 'danger')
        
        return redirect(url_for('web.settings'))
        
    except Exception as e:
        db.session.rollback()
        AuditLog.log_event(
            'system_reset', 'system', 'reset', 'failure',
            user=current_user, ip_address=request.remote_addr,
            details={'error': str(e), 'reset_type': reset_type}
        )
        flash(f'Error resetting system: {str(e)}', 'error')
        return redirect(url_for('web.settings'))

@web_bp.route('/certificates/<int:cert_id>/verify-chain', methods=['GET'])
@login_required
def verify_chain(cert_id):
    """Verify certificate chain"""
    try:
        from app.pki.ca import CertificateAuthority
        import yaml
        
        # Get certificate
        cert = Certificate.query.get_or_404(cert_id)
        
        # Load config
        with open('config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Use ca_path as the storage path (where CA certificates are stored)
        storage_path = Path(config['storage']['ca_path'])
        
        # Initialize CA
        ca = CertificateAuthority(config, storage_path)
        
        # Verify chain
        results = ca.verify_certificate_chain(cert.certificate_pem)
        
        # Log the verification
        AuditLog.log_event(
            'certificate_verify_chain', 'pki', 'verify', 'success',
            user=current_user, ip_address=request.remote_addr,
            resource_type='certificate', resource_id=cert.serial_number,
            details={'valid': results['valid'], 'errors': results['errors']}
        )
        
        return render_template('verify_chain.html', 
                             certificate=cert, 
                             verification=results)
        
    except Exception as e:
        AuditLog.log_event(
            'certificate_verify_chain', 'pki', 'verify', 'failure',
            user=current_user, ip_address=request.remote_addr,
            resource_type='certificate', resource_id=cert_id,
            details={'error': str(e)}
        )
        flash(f'Error verifying certificate chain: {str(e)}', 'error')
        return redirect(url_for('web.certificate_detail', cert_id=cert_id))
