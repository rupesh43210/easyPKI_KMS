#!/usr/bin/env python3
"""
CLI tool for PKI operations
"""
import click
import sys
from pathlib import Path
from tabulate import tabulate
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import Certificate, User
from app.pki.ca import CertificateAuthority
from app.utils.config import load_config

@click.group()
def cli():
    """PKI Management CLI Tool"""
    pass

@cli.group()
def cert():
    """Certificate management commands"""
    pass

@cert.command()
@click.option('--cn', '--common-name', required=True, help='Common Name for the certificate')
@click.option('--type', 'cert_type', default='server', type=click.Choice(['server', 'client', 'email', 'code_signing']),
              help='Certificate type')
@click.option('--days', default=365, help='Validity period in days')
@click.option('--san', multiple=True, help='Subject Alternative Names')
@click.option('--org', help='Organization name')
def create(cn, cert_type, days, san, org):
    """Create a new certificate"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        try:
            ca = CertificateAuthority(config, config['storage']['ca_path'])
            private_key, cert = ca.create_certificate(
                common_name=cn,
                cert_type=cert_type,
                validity_days=days,
                san_list=list(san) if san else None,
                organization=org
            )
            
            # Save to database
            from cryptography.hazmat.primitives import serialization
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            
            # Get system user
            system_user = User.query.filter_by(username='admin').first()
            
            db_cert = Certificate(
                serial_number=format(cert.serial_number, 'x'),
                common_name=cn,
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                cert_type=cert_type,
                key_algorithm='RSA',
                key_size=2048,
                hash_algorithm='SHA256',
                not_before=cert.not_valid_before,
                not_after=cert.not_valid_after,
                status='active',
                certificate_pem=cert_pem,
                created_by_id=system_user.id
            )
            
            db.session.add(db_cert)
            db.session.commit()
            
            click.echo(f"✅ Certificate created successfully!")
            click.echo(f"   Serial: {db_cert.serial_number}")
            click.echo(f"   Common Name: {cn}")
            click.echo(f"   Valid until: {cert.not_valid_after}")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}", err=True)
            sys.exit(1)

@cert.command()
@click.option('--status', type=click.Choice(['active', 'revoked', 'expired', 'all']), default='all',
              help='Filter by status')
@click.option('--type', 'cert_type', help='Filter by certificate type')
def list(status, cert_type):
    """List all certificates"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        query = Certificate.query
        
        if status != 'all':
            query = query.filter_by(status=status)
        
        if cert_type:
            query = query.filter_by(cert_type=cert_type)
        
        certs = query.all()
        
        if not certs:
            click.echo("No certificates found.")
            return
        
        table_data = []
        for cert in certs:
            table_data.append([
                cert.id,
                cert.serial_number[:16] + '...',
                cert.common_name,
                cert.cert_type,
                cert.status,
                cert.not_after.strftime('%Y-%m-%d'),
                f"{cert.days_until_expiry()} days"
            ])
        
        headers = ['ID', 'Serial', 'Common Name', 'Type', 'Status', 'Expires', 'Days Left']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
        click.echo(f"\nTotal: {len(certs)} certificates")

@cert.command()
@click.option('--serial', required=True, help='Certificate serial number')
@click.option('--reason', default='unspecified', help='Revocation reason')
def revoke(serial, reason):
    """Revoke a certificate"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        cert = Certificate.query.filter_by(serial_number=serial).first()
        
        if not cert:
            click.echo(f"❌ Certificate not found: {serial}", err=True)
            sys.exit(1)
        
        if cert.status == 'revoked':
            click.echo("❌ Certificate is already revoked", err=True)
            sys.exit(1)
        
        cert.status = 'revoked'
        cert.revoked_at = datetime.utcnow()
        cert.revocation_reason = reason
        
        db.session.commit()
        
        click.echo(f"✅ Certificate revoked successfully!")
        click.echo(f"   Serial: {serial}")
        click.echo(f"   Reason: {reason}")

@cert.command()
@click.option('--id', 'cert_id', type=int, required=True, help='Certificate ID')
def info(cert_id):
    """Show detailed certificate information"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        cert = Certificate.query.get(cert_id)
        
        if not cert:
            click.echo(f"❌ Certificate not found: {cert_id}", err=True)
            sys.exit(1)
        
        click.echo("\n" + "="*60)
        click.echo("CERTIFICATE INFORMATION")
        click.echo("="*60)
        click.echo(f"ID:              {cert.id}")
        click.echo(f"Serial Number:   {cert.serial_number}")
        click.echo(f"Common Name:     {cert.common_name}")
        click.echo(f"Type:            {cert.cert_type}")
        click.echo(f"Status:          {cert.status}")
        click.echo(f"Subject:         {cert.subject}")
        click.echo(f"Issuer:          {cert.issuer}")
        click.echo(f"Key Algorithm:   {cert.key_algorithm}-{cert.key_size}")
        click.echo(f"Hash Algorithm:  {cert.hash_algorithm}")
        click.echo(f"Not Before:      {cert.not_before}")
        click.echo(f"Not After:       {cert.not_after}")
        click.echo(f"Days Left:       {cert.days_until_expiry()}")
        click.echo(f"Created At:      {cert.created_at}")
        click.echo(f"Created By:      {cert.created_by.username}")
        
        if cert.revoked_at:
            click.echo(f"Revoked At:      {cert.revoked_at}")
            click.echo(f"Revoke Reason:   {cert.revocation_reason}")
        
        click.echo("="*60 + "\n")

if __name__ == '__main__':
    cli()
