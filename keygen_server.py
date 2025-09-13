#!/usr/bin/env python3
"""
Server key generation utility
Generates Dilithium signing keys for server authentication
"""

import os
import sys
import click
from crypto_utils import QuantumSafeCrypto, save_key_to_file, CryptoError

@click.command()
@click.option('--output-dir', default='keys', help='Output directory for keys')
@click.option('--force', is_flag=True, help='Overwrite existing keys')
def main(output_dir: str, force: bool):
    """Generate server cryptographic keys"""
    
    print("🔐 Quantum-Safe VPN - Server Key Generation")
    print("=" * 50)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Key file paths
    dilithium_private_path = os.path.join(output_dir, "server_dilithium.pem")
    dilithium_public_path = os.path.join(output_dir, "server_dilithium_public.pem")
    
    # Check if keys already exist
    if not force and (os.path.exists(dilithium_private_path) or os.path.exists(dilithium_public_path)):
        print("❌ Server keys already exist. Use --force to overwrite.")
        sys.exit(1)
    
    try:
        # Generate Dilithium keypair for server authentication
        print("🔄 Generating Dilithium signature keypair...")
        dilithium_public, dilithium_private = QuantumSafeCrypto.generate_dilithium_keypair()
        
        # Save keys
        print("💾 Saving keys...")
        save_key_to_file(dilithium_private, dilithium_private_path)
        save_key_to_file(dilithium_public, dilithium_public_path)
        
        # Display key information
        print("\n✅ Server keys generated successfully:")
        print(f"   Private key: {dilithium_private_path} ({len(dilithium_private)} bytes)")
        print(f"   Public key:  {dilithium_public_path} ({len(dilithium_public)} bytes)")
        print(f"   Permissions: 600 (private key only)")
        
        # Show key fingerprints
        import hashlib
        private_fingerprint = hashlib.sha256(dilithium_private).hexdigest()[:16]
        public_fingerprint = hashlib.sha256(dilithium_public).hexdigest()[:16]
        
        print(f"\n🔍 Key fingerprints:")
        print(f"   Private: {private_fingerprint}...")
        print(f"   Public:  {public_fingerprint}...")
        
        print(f"\n📁 Keys saved in: {os.path.abspath(output_dir)}")
        
    except CryptoError as e:
        print(f"❌ Cryptographic error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()