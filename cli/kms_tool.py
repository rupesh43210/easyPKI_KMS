#!/usr/bin/env python3
"""
CLI tool for KMS operations
"""
import click
import sys
from pathlib import Path
from tabulate import tabulate

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import Key, User
from app.kms.kms import KeyManagementSystem
from app.utils.config import load_config

@click.group()
def cli():
    """KMS Management CLI Tool"""
    pass

@cli.group()
def key():
    """Key management commands"""
    pass

@key.command()
@click.option('--name', required=True, help='Key name')
@click.option('--type', 'key_type', default='symmetric', 
              type=click.Choice(['symmetric', 'asymmetric']), help='Key type')
@click.option('--algorithm', default='AES-256', help='Algorithm (e.g., AES-256, RSA-2048)')
@click.option('--purpose', default='encryption', 
              type=click.Choice(['encryption', 'signing', 'key_wrapping']), help='Key purpose')
@click.option('--rotation-days', default=90, help='Rotation policy in days')
def create(name, key_type, algorithm, purpose, rotation_days):
    """Create a new key"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        try:
            kms = KeyManagementSystem(config, config['storage']['keys_path'])
            
            # Generate key
            if key_type == 'symmetric':
                key_data = kms.generate_symmetric_key(algorithm, purpose)
            else:
                key_data = kms.generate_asymmetric_key(algorithm, purpose)
            
            # Get system user
            system_user = User.query.filter_by(username='admin').first()
            
            # Create key ID
            import secrets
            key_id = secrets.token_urlsafe(32)
            
            from datetime import datetime, timedelta
            next_rotation = datetime.utcnow() + timedelta(days=rotation_days) if rotation_days else None
            
            db_key = Key(
                key_id=key_id,
                name=name,
                key_type=key_type,
                algorithm=algorithm,
                key_size=key_data.get('key_size'),
                purpose=purpose,
                status='active',
                encrypted_key_material=key_data['key_material'],
                version=1,
                rotation_policy_days=rotation_days,
                next_rotation_at=next_rotation,
                created_by_id=system_user.id
            )
            
            db.session.add(db_key)
            db.session.commit()
            
            click.echo(f"✅ Key created successfully!")
            click.echo(f"   ID: {key_id}")
            click.echo(f"   Name: {name}")
            click.echo(f"   Algorithm: {algorithm}")
            click.echo(f"   Next rotation: {next_rotation.strftime('%Y-%m-%d') if next_rotation else 'Never'}")
            
        except Exception as e:
            click.echo(f"❌ Error: {e}", err=True)
            sys.exit(1)

@key.command()
@click.option('--status', type=click.Choice(['active', 'disabled', 'all']), default='all',
              help='Filter by status')
def list(status):
    """List all keys"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        query = Key.query
        
        if status != 'all':
            query = query.filter_by(status=status)
        
        keys = query.all()
        
        if not keys:
            click.echo("No keys found.")
            return
        
        table_data = []
        for k in keys:
            table_data.append([
                k.id,
                k.key_id[:16] + '...',
                k.name,
                k.key_type,
                k.algorithm,
                k.purpose,
                k.status,
                f"v{k.version}",
                f"{k.days_until_rotation() or 'N/A'}"
            ])
        
        headers = ['ID', 'Key ID', 'Name', 'Type', 'Algorithm', 'Purpose', 'Status', 'Version', 'Days to Rotate']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
        click.echo(f"\nTotal: {len(keys)} keys")

@key.command()
@click.option('--id', 'key_id', type=int, required=True, help='Key ID')
def info(key_id):
    """Show detailed key information"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        key = Key.query.get(key_id)
        
        if not key:
            click.echo(f"❌ Key not found: {key_id}", err=True)
            sys.exit(1)
        
        click.echo("\n" + "="*60)
        click.echo("KEY INFORMATION")
        click.echo("="*60)
        click.echo(f"ID:              {key.id}")
        click.echo(f"Key ID:          {key.key_id}")
        click.echo(f"Name:            {key.name}")
        click.echo(f"Description:     {key.description or 'N/A'}")
        click.echo(f"Type:            {key.key_type}")
        click.echo(f"Algorithm:       {key.algorithm}")
        click.echo(f"Purpose:         {key.purpose}")
        click.echo(f"Status:          {key.status}")
        click.echo(f"Version:         {key.version}")
        click.echo(f"Rotation Policy: {key.rotation_policy_days or 'None'} days")
        click.echo(f"Next Rotation:   {key.next_rotation_at or 'N/A'}")
        click.echo(f"Days to Rotate:  {key.days_until_rotation() or 'N/A'}")
        click.echo(f"Access Count:    {key.accessed_count}")
        click.echo(f"Last Accessed:   {key.last_accessed_at or 'Never'}")
        click.echo(f"Created At:      {key.created_at}")
        click.echo(f"Created By:      {key.created_by.username}")
        click.echo("="*60 + "\n")

@key.command()
@click.option('--id', 'key_id', type=int, required=True, help='Key ID')
@click.option('--text', required=True, help='Text to encrypt')
def encrypt(key_id, text):
    """Encrypt text with a key"""
    config = load_config()
    app = create_app(config)
    
    with app.app_context():
        key = Key.query.get(key_id)
        
        if not key:
            click.echo(f"❌ Key not found: {key_id}", err=True)
            sys.exit(1)
        
        if key.status != 'active':
            click.echo(f"❌ Key is not active", err=True)
            sys.exit(1)
        
        try:
            kms = KeyManagementSystem(config, config['storage']['keys_path'])
            encrypted = kms.encrypt_data(key.key_id, text, key.encrypted_key_material)
            
            click.echo("✅ Encryption successful!")
            click.echo(f"\nEncrypted data (save this to decrypt later):")
            import json
            click.echo(json.dumps(encrypted, indent=2))
            
        except Exception as e:
            click.echo(f"❌ Error: {e}", err=True)
            sys.exit(1)

if __name__ == '__main__':
    cli()
