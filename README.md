# Quantum-Safe VPN Prototype

A hackathon-ready VPN implementation using post-quantum cryptography (CRYSTALS-Kyber, CRYSTALS-Dilithium) combined with classical X25519 for hybrid security.

## Features

- **Hybrid Key Exchange**: CRYSTALS-Kyber + X25519 ECDH
- **Post-Quantum Signatures**: CRYSTALS-Dilithium for authentication
- **Modern Encryption**: AES-256-GCM with HKDF-derived keys
- **TUN-based Tunneling**: Layer 3 VPN with IPv4 support
- **Clean Architecture**: Modular, hackathon-ready codebase

## Installation

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake ninja-build python3-dev python3-pip

# Install liboqs (Open Quantum Safe library)
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig
cd ../..
```

### Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

### TUN Interface Setup

```bash
# Enable IP forwarding (required for server)
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Allow TUN interface creation (add to sudoers if needed)
# The scripts will create tun0 interface automatically
```

## Usage

### Quick Demo

```bash
# Make scripts executable
chmod +x *.py *.sh

# Run the complete demo
sudo ./demo.sh
```

### Manual Usage

1. **Generate Keys**:
```bash
python3 keygen_server.py
python3 keygen_client.py
```

2. **Start Server** (in terminal 1):
```bash
sudo python3 server.py --host 0.0.0.0 --port 8443
```

3. **Start Client** (in terminal 2):
```bash
sudo python3 client.py --server 127.0.0.1 --port 8443
```

4. **Test Connection** (in terminal 3):
```bash
# Client gets 10.8.0.2, server is 10.8.0.1
curl --interface tun0 http://10.8.0.1:8080/test
ping -I tun0 10.8.0.1
```

## Architecture

### Cryptographic Design

1. **Handshake Protocol**:
   - Server sends Dilithium public key + signature
   - Client verifies signature, sends Kyber ciphertext + X25519 public key
   - Server decapsulates Kyber, performs X25519 ECDH
   - Both sides derive session key using HKDF-SHA256

2. **Session Key Derivation**:
   ```
   shared_secret = kyber_shared_secret || x25519_shared_secret
   session_key = HKDF-SHA256(shared_secret, salt="qsafe-vpn-2024", info="session", length=32)
   ```

3. **Packet Encryption**:
   - AES-256-GCM with 12-byte random nonces
   - Additional Authenticated Data (AAD) includes session ID
   - Each packet: [4-byte length][12-byte nonce][encrypted payload][16-byte tag]

### Network Architecture

```
Client TUN (10.8.0.2/24) <---> Client App <---> UDP Socket <---> Server App <---> Server TUN (10.8.0.1/24)
```

## File Structure

```
quantum-safe-vpn/
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── demo.sh               # Complete demo script
├── keygen_server.py      # Server key generation
├── keygen_client.py      # Client key generation
├── server.py             # VPN server
├── client.py             # VPN client
├── crypto_utils.py       # Cryptographic utilities
├── tun_utils.py          # TUN interface utilities
├── protocol.py           # Protocol definitions
└── keys/                 # Generated keys directory
    ├── server_dilithium.pem
    ├── server_dilithium_public.pem
    ├── client_dilithium.pem
    └── client_dilithium_public.pem
```

## Security Notes

⚠️  **This is a prototype for demonstration purposes**:
- Not audited for production use
- Requires root privileges for TUN interfaces
- Uses UDP (no built-in reliability)
- No key rotation or perfect forward secrecy
- Simplified error handling

## Troubleshooting

1. **Permission Denied**: Run with `sudo` for TUN interface access
2. **liboqs not found**: Ensure liboqs is installed and `ldconfig` was run
3. **TUN interface errors**: Check if `/dev/net/tun` exists
4. **Connection refused**: Verify firewall settings and server binding

## License

MIT License - Built for hackathon/educational purposes.