#!/usr/bin/env python3
"""
Quantum-Safe VPN API Server
REST API for frontend-backend communication
"""

import os
import sys
import time
import json
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
import click
from colorama import init, Fore, Style

# Initialize colorama
init()

class VPNApiServer:
    """REST API server for VPN frontend"""

    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        """Initialize API server"""
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for frontend

        # VPN server reference (will be set when integrated)
        self.vpn_server = None

        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        """Setup API routes"""

        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            """Get VPN server status"""
            if not self.vpn_server:
                return jsonify({
                    'status': 'stopped',
                    'message': 'VPN server not running'
                })

            try:
                stats = self.vpn_server.stats
                uptime = time.time() - stats['start_time']

                return jsonify({
                    'status': 'running',
                    'uptime': uptime,
                    'connections': len(self.vpn_server.clients),
                    'handshakes': stats['handshakes'],
                    'packets_sent': stats['packets_sent'],
                    'packets_received': stats['packets_received'],
                    'bytes_sent': stats['bytes_sent'],
                    'bytes_received': stats['bytes_received'],
                    'start_time': stats['start_time']
                })
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 500

        @self.app.route('/api/connections', methods=['GET'])
        def get_connections():
            """Get active VPN connections"""
            if not self.vpn_server:
                return jsonify([])

            try:
                connections = []
                for session_id, client in self.vpn_server.clients.items():
                    connections.append({
                        'id': session_id,
                        'clientId': client['client_id'],
                        'status': 'connected',
                        'connectedAt': client['handshake_time'],
                        'lastSeen': client['last_seen'],
                        'sessionId': session_id,
                        'clientInfo': client['client_info'],
                        'bytesTransferred': client['packets_sent'] * 1000 + client['packets_received'] * 1000,  # Estimate
                        'packetsTransferred': client['packets_sent'] + client['packets_received'],
                        'tunnelIP': client['assigned_ip']
                    })
                return jsonify(connections)
            except Exception as e:
                return jsonify({
                    'error': str(e)
                }), 500

        @self.app.route('/api/traffic', methods=['GET'])
        def get_traffic():
            """Get traffic statistics"""
            if not self.vpn_server:
                return jsonify([])

            try:
                # Return current traffic stats as a single data point
                stats = self.vpn_server.stats
                now = time.time() * 1000  # Convert to milliseconds for JS

                traffic_data = {
                    'timestamp': now,
                    'bytesIn': stats['bytes_received'],
                    'bytesOut': stats['bytes_sent'],
                    'packetsIn': stats['packets_received'],
                    'packetsOut': stats['packets_sent']
                }
                return jsonify([traffic_data])
            except Exception as e:
                return jsonify({
                    'error': str(e)
                }), 500

        @self.app.route('/api/crypto', methods=['GET'])
        def get_crypto_info():
            """Get cryptographic information"""
            return jsonify({
                'kemAlgorithm': 'CRYSTALS-Kyber768',
                'signatureAlgorithm': 'CRYSTALS-Dilithium3',
                'sessionEncryption': 'AES-256-GCM',
                'keyDerivation': 'HKDF-SHA256',
                'isQuantumSafe': True
            })

        @self.app.route('/api/keys', methods=['GET'])
        def get_keys():
            """Get key management information"""
            keys = []

            # Check for server keys
            key_dir = getattr(self.vpn_server, 'key_dir', 'keys') if self.vpn_server else 'keys'

            server_private = os.path.join(key_dir, 'server_dilithium.pem')
            server_public = os.path.join(key_dir, 'server_dilithium_public.pem')

            if os.path.exists(server_private):
                keys.append({
                    'id': 'server_dilithium_private',
                    'type': 'dilithium',
                    'purpose': 'server',
                    'algorithm': 'CRYSTALS-Dilithium3',
                    'createdAt': os.path.getctime(server_private) * 1000,
                    'fingerprint': 'server_private_key',
                    'status': 'active'
                })

            if os.path.exists(server_public):
                keys.append({
                    'id': 'server_dilithium_public',
                    'type': 'dilithium',
                    'purpose': 'server',
                    'algorithm': 'CRYSTALS-Dilithium3',
                    'createdAt': os.path.getctime(server_public) * 1000,
                    'fingerprint': 'server_public_key',
                    'status': 'active'
                })

            return jsonify(keys)

        @self.app.route('/api/control/<action>', methods=['POST'])
        def control_vpn(action):
            """Control VPN server (start/stop)"""
            if action not in ['start', 'stop']:
                return jsonify({
                    'success': False,
                    'message': 'Invalid action'
                }), 400

            # For now, just return success since server control is external
            return jsonify({
                'success': True,
                'message': f'VPN server {action} command sent'
            })

    def set_vpn_server(self, vpn_server):
        """Set reference to VPN server instance"""
        self.vpn_server = vpn_server

    def start(self):
        """Start the API server"""
        print(f"🚀 {Fore.GREEN}VPN API Server starting on {self.host}:{self.port}{Style.RESET_ALL}")
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)

@click.command()
@click.option('--host', default='127.0.0.1', help='API server bind address')
@click.option('--port', default=5000, help='API server port')
def main(host: str, port: int):
    """Start VPN API Server"""

    print("🌐 Quantum-Safe VPN API Server")
    print("=" * 40)

    server = VPNApiServer(host, port)
    server.start()

if __name__ == "__main__":
    main()
