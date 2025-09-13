#!/usr/bin/env python3
"""
Client key generation utility
Generates keys for client authentication (optional)
"""

import os
import sys
import click
from crypto_utils import QuantumSafeCrypto, save_key_to_file, CryptoError

@click.command()
@click.option('--output-dir', default='keys', help='Output directory for keys')
@click.option('--force', is_flag=True, help='Overwrite existing keys')
@click.option('--client-auth', is_flag=True, help='Generate client authentication keys')
def main(output_dir: str, force: bool, client_auth: bool):
    """Generate client cryptographic keys"""
    
    print("🔐 Quantum-Safe VPN - Client Key Generation")
    print("=" * 50)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    if client_auth:
        # Key file paths for client authentication
        dilithium_private_path = os.path.join(output_dir, "client_dilithium.pem")
        dilithium_public_path = os.path.join(output_dir, "client_dilithium_public.pem")
        
        # Check if keys already exist
        if not force and (os.path.exists(dilithium_private_path) or os.path.exists(dilithium_public_path)):
            print("❌ Client keys already exist. Use --force to overwrite.")
            sys.exit(1)
        
        try:
            # Generate Dilithium keypair for client authentication
            print("🔄 Generating client Dilithium signature keypair...")
            dilithium_public, dilithium_private = QuantumSafeCrypto.generate_dilithium_keypair()
            
            # Save keys
            print("💾 Saving keys...")
            save_key_to_file(dilithium_private, dilithium_private_path)
            save_key_to_file(dilithium_public, dilithium_public_path)
            
            # Display key information
            print("\n✅ Client authentication keys generated successfully:")
            print(f"   Private key: {dilithium_private_path} ({len(dilithium_private)} bytes)")
            print(f"   Public key:  {dilithium_public_path} ({len(dilithium_public)} bytes)")
            
            # Show key fingerprints
            import hashlib
            private_fingerprint = hashlib.sha256(dilithium_private).hexdigest()[:16]
            public_fingerprint = hashlib.sha256(dilithium_public).hexdigest()[:16]
            
            print(f"\n🔍 Key fingerprints:")
            print(f"   Private: {private_fingerprint}...")
            print(f"   Public:  {public_fingerprint}...")
            
        except CryptoError as e:
            print(f"❌ Cryptographic error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            sys.exit(1)
    else:
        print("ℹ️  Basic client setup (no authentication keys needed)")
        print("   Client uses ephemeral X25519 keys generated during handshake")
        print("   Server authentication is handled by server's Dilithium keys")
    
    print(f"\n📁 Keys directory: {os.path.abspath(output_dir)}")
    print("\n💡 Next steps:")
    print("   1. Run server: sudo python3 server.py")
    print("   2. Run client: sudo python3 client.py")

if __name__ == "__main__":
    main()