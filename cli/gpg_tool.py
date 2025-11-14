#!/usr/bin/env python3
"""
GPG Tool - Command-line interface for GPG operations
"""

import click
import sys
import os
from pathlib import Path
from tabulate import tabulate

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.gpg import GPGManager


@click.group()
def cli():
    """GPG Key Management Tool"""
    pass


@cli.command()
@click.option('--name', required=True, help='Real name for the key')
@click.option('--email', required=True, help='Email address')
@click.option('--comment', default='', help='Optional comment')
@click.option('--key-type', default='RSA', type=click.Choice(['RSA', 'DSA', 'ECDSA']), help='Key type')
@click.option('--key-length', default=4096, type=click.Choice([2048, 3072, 4096]), help='Key length in bits')
@click.option('--expire-date', default='0', help='Expiration date (0=never, or YYYY-MM-DD)')
@click.option('--passphrase', prompt=True, hide_input=True, confirmation_prompt=True, help='Passphrase to protect the key')
def generate(name, email, comment, key_type, key_length, expire_date, passphrase):
    """Generate a new GPG key pair"""
    try:
        gpg = GPGManager()
        
        click.echo(f"\n🔐 Generating {key_type}-{key_length} GPG key...")
        click.echo(f"   Name: {name}")
        click.echo(f"   Email: {email}")
        
        result = gpg.generate_key(
            name_real=name,
            name_email=email,
            name_comment=comment,
            key_type=key_type,
            key_length=key_length,
            expire_date=expire_date,
            passphrase=passphrase
        )
        
        if result.get('success'):
            click.echo(f"\n✅ Key generated successfully!")
            click.echo(f"   Fingerprint: {result['fingerprint']}")
            click.echo(f"   Key ID: {result['key_id']}")
            click.echo(f"   Created: {result['created']}")
        else:
            click.echo(f"\n❌ Failed to generate key: {result.get('error')}", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--secret', is_flag=True, help='List private keys instead of public keys')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']), help='Output format')
def list(secret, output_format):
    """List all GPG keys"""
    try:
        gpg = GPGManager()
        keys = gpg.list_keys(secret=secret)
        
        if not keys:
            click.echo(f"\nℹ️  No {'private' if secret else 'public'} keys found")
            return
        
        if output_format == 'json':
            import json
            click.echo(json.dumps(keys, indent=2))
        else:
            click.echo(f"\n🔑 {'Private' if secret else 'Public'} GPG Keys ({len(keys)} total):\n")
            
            table_data = []
            for key in keys:
                uids = ', '.join(key.get('uids', []))
                table_data.append([
                    key.get('key_id', '')[:16],
                    key.get('type', ''),
                    key.get('length', ''),
                    uids[:50],
                    key.get('created', '')
                ])
            
            headers = ['Key ID', 'Type', 'Length', 'UIDs', 'Created']
            click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('fingerprint')
@click.option('--secret', is_flag=True, help='Show private key info')
def info(fingerprint, secret):
    """Get detailed information about a GPG key"""
    try:
        gpg = GPGManager()
        key_info = gpg.get_key_info(fingerprint, secret=secret)
        
        if not key_info:
            click.echo(f"\n❌ Key not found: {fingerprint}", err=True)
            sys.exit(1)
        
        click.echo(f"\n🔑 GPG Key Information:\n")
        click.echo(f"Fingerprint:  {key_info.get('fingerprint')}")
        click.echo(f"Key ID:       {key_info.get('key_id')}")
        click.echo(f"Type:         {key_info.get('type')}")
        click.echo(f"Length:       {key_info.get('length')} bits")
        click.echo(f"Algorithm:    {key_info.get('algorithm')}")
        click.echo(f"Created:      {key_info.get('created')}")
        click.echo(f"Expires:      {key_info.get('expires') or 'Never'}")
        click.echo(f"Trust:        {key_info.get('trust')}")
        click.echo(f"\nUIDs:")
        for uid in key_info.get('uids', []):
            click.echo(f"  • {uid}")
        
        if key_info.get('subkeys'):
            click.echo(f"\nSubkeys: {len(key_info['subkeys'])}")
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('fingerprint')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--secret', is_flag=True, help='Export private key')
@click.option('--passphrase', help='Passphrase for private key (will prompt if not provided)')
def export(fingerprint, output, secret, passphrase):
    """Export a GPG key"""
    try:
        gpg = GPGManager()
        
        if secret and not passphrase:
            passphrase = click.prompt('Passphrase', hide_input=True)
        
        if secret:
            key_data = gpg.export_private_key(fingerprint, passphrase=passphrase)
        else:
            key_data = gpg.export_public_key(fingerprint)
        
        if not key_data:
            click.echo(f"\n❌ Failed to export key (key not found or incorrect passphrase)", err=True)
            sys.exit(1)
        
        if output:
            with open(output, 'w') as f:
                f.write(key_data)
            click.echo(f"\n✅ Key exported to: {output}")
        else:
            click.echo(key_data)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('key_file', type=click.File('r'))
def import_key(key_file):
    """Import a GPG key from file"""
    try:
        gpg = GPGManager()
        key_data = key_file.read()
        
        result = gpg.import_key(key_data)
        
        if result.get('success'):
            click.echo(f"\n✅ Successfully imported {result['count']} key(s)")
            for fp in result.get('fingerprints', []):
                click.echo(f"   Fingerprint: {fp}")
        else:
            click.echo(f"\n❌ Failed to import key: {result.get('error')}", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('fingerprint')
@click.option('--secret', is_flag=True, help='Delete private key')
@click.option('--passphrase', help='Passphrase for private key')
@click.confirmation_option(prompt='Are you sure you want to delete this key?')
def delete(fingerprint, secret, passphrase):
    """Delete a GPG key"""
    try:
        gpg = GPGManager()
        
        if secret and not passphrase:
            passphrase = click.prompt('Passphrase', hide_input=True)
        
        success = gpg.delete_key(fingerprint, secret=secret, passphrase=passphrase)
        
        if success:
            click.echo(f"\n✅ Key deleted: {fingerprint}")
        else:
            click.echo(f"\n❌ Failed to delete key", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--data', help='Data to encrypt (or use --file)')
@click.option('--file', '-f', 'input_file', type=click.File('r'), help='Input file to encrypt')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--recipient', '-r', multiple=True, required=True, help='Recipient email or fingerprint (can specify multiple)')
@click.option('--sign', help='Sign with this key (fingerprint)')
@click.option('--passphrase', help='Passphrase for signing key')
def encrypt(data, input_file, output, recipient, sign, passphrase):
    """Encrypt data with GPG"""
    try:
        gpg = GPGManager()
        
        # Get data to encrypt
        if input_file:
            data = input_file.read()
        elif not data:
            click.echo("❌ Error: Must provide either --data or --file", err=True)
            sys.exit(1)
        
        encrypted = gpg.encrypt(
            data=data,
            recipients=list(recipient),
            sign=sign,
            passphrase=passphrase
        )
        
        if encrypted:
            if output:
                with open(output, 'w') as f:
                    f.write(encrypted)
                click.echo(f"\n✅ Data encrypted and saved to: {output}")
            else:
                click.echo(encrypted)
        else:
            click.echo(f"\n❌ Encryption failed", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--data', help='Encrypted data (or use --file)')
@click.option('--file', '-f', 'input_file', type=click.File('r'), help='Encrypted file')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--passphrase', prompt=True, hide_input=True, help='Passphrase to unlock private key')
def decrypt(data, input_file, output, passphrase):
    """Decrypt GPG encrypted data"""
    try:
        gpg = GPGManager()
        
        # Get data to decrypt
        if input_file:
            data = input_file.read()
        elif not data:
            click.echo("❌ Error: Must provide either --data or --file", err=True)
            sys.exit(1)
        
        decrypted, metadata = gpg.decrypt(data, passphrase=passphrase)
        
        if decrypted:
            if output:
                with open(output, 'w') as f:
                    f.write(decrypted)
                click.echo(f"\n✅ Data decrypted and saved to: {output}")
            else:
                click.echo(decrypted)
            
            if metadata.get('username'):
                click.echo(f"\n📋 Metadata:", err=True)
                click.echo(f"   Signed by: {metadata.get('username')}", err=True)
                click.echo(f"   Key ID: {metadata.get('key_id')}", err=True)
        else:
            click.echo(f"\n❌ Decryption failed: {metadata.get('error')}", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--data', help='Data to sign (or use --file)')
@click.option('--file', '-f', 'input_file', type=click.File('r'), help='Input file to sign')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--keyid', required=True, help='Key ID or fingerprint to sign with')
@click.option('--passphrase', prompt=True, hide_input=True, help='Passphrase to unlock key')
@click.option('--detach', is_flag=True, default=True, help='Create detached signature')
@click.option('--clearsign', is_flag=True, help='Create cleartext signature')
def sign(data, input_file, output, keyid, passphrase, detach, clearsign):
    """Sign data with GPG"""
    try:
        gpg = GPGManager()
        
        # Get data to sign
        if input_file:
            data = input_file.read()
        elif not data:
            click.echo("❌ Error: Must provide either --data or --file", err=True)
            sys.exit(1)
        
        signature = gpg.sign(
            data=data,
            keyid=keyid,
            passphrase=passphrase,
            detach=detach and not clearsign,
            clearsign=clearsign
        )
        
        if signature:
            if output:
                with open(output, 'w') as f:
                    f.write(signature)
                click.echo(f"\n✅ Signature created and saved to: {output}")
            else:
                click.echo(signature)
        else:
            click.echo(f"\n❌ Signing failed", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--data', help='Signed data (or use --file)')
@click.option('--file', '-f', 'input_file', type=click.File('r'), help='Signed file')
@click.option('--signature', type=click.File('r'), help='Detached signature file')
def verify(data, input_file, signature):
    """Verify GPG signature"""
    try:
        gpg = GPGManager()
        
        # Get data to verify
        if input_file:
            data = input_file.read()
        elif not data:
            click.echo("❌ Error: Must provide either --data or --file", err=True)
            sys.exit(1)
        
        # Get signature if detached
        sig_data = signature.read() if signature else None
        
        result = gpg.verify(data, signature=sig_data)
        
        if result.get('valid'):
            click.echo(f"\n✅ Valid signature!")
            click.echo(f"   Signed by: {result.get('username')}")
            click.echo(f"   Key ID: {result.get('key_id')}")
            click.echo(f"   Fingerprint: {result.get('fingerprint')}")
            click.echo(f"   Trust level: {result.get('trust_text')}")
            if result.get('timestamp'):
                click.echo(f"   Timestamp: {result.get('timestamp')}")
        else:
            click.echo(f"\n❌ Invalid signature!", err=True)
            if result.get('error'):
                click.echo(f"   Error: {result['error']}", err=True)
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
