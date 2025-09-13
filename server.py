#!/usr/bin/env python3
"""
Quantum-Safe VPN Server
Implements post-quantum secure VPN server with TUN interface
"""

import os
import sys
import time
import socket
import threading
import signal
import subprocess
from typing import Dict, Optional, Tuple
import click
from colorama import init, Fore, Style

from crypto_utils import (
    QuantumSafeCrypto, SessionCrypto, CryptoError,
    load_key_from_file, truncate_hex
)
from cryptography.hazmat.primitives import serialization
from tun_utils import TUNInterface, parse_ip_packet, check_tun_support
from protocol import (
    Message, MessageType, HandshakeInit, HandshakeResponse, HandshakeComplete,
    VPNProtocol, ProtocolError, validate_message_size, CONNECTION_TIMEOUT
)
from vpn_setup import VPNSetup

# Initialize colorama for cross-platform colored output
init()

# Enable IP forwarding if not already
subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
# Set up iptables for NAT (assuming tun0 interface)
subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE'], check=True)  # Adjust eth0 to your external interface
subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', 'tun0', '-o', 'eth0', '-j', 'ACCEPT'], check=True)
subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', 'tun0', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)

class VPNServer:
    """Quantum-Safe VPN Server"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443, key_dir: str = "keys"):
        """Initialize VPN server"""
        self.host = host
        self.port = port
        self.key_dir = key_dir
        self.running = False
        self.clients = {}  # session_id -> client info
        self.ip_to_session = {}  # assigned_ip -> session_id
        self.assigned_ips = set()  # track assigned IPs
        
        # Network components
        self.socket = None
        self.tun = None
        
        # Cryptographic keys
        self.dilithium_private = None
        self.dilithium_public = None
        self.kyber_private = None
        self.kyber_public = None
        
        # Statistics
        self.stats = {
            "handshakes": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "start_time": time.time()
        }
        
        # Enable IP forwarding
        self._enable_ip_forwarding()
        
        # Load server keys
        self._load_keys()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_keys(self) -> None:
        """Load server cryptographic keys"""
        try:
            dilithium_private_path = os.path.join(self.key_dir, "server_dilithium.pem")
            dilithium_public_path = os.path.join(self.key_dir, "server_dilithium_public.pem")
            kyber_private_path = os.path.join(self.key_dir, "server_kyber.pem")
            kyber_public_path = os.path.join(self.key_dir, "server_kyber_public.pem")

            if not os.path.exists(dilithium_private_path) or not os.path.exists(dilithium_public_path):
                raise CryptoError("Server Dilithium keys not found. Run 'python3 keygen_server.py' first.")

            if not os.path.exists(kyber_private_path) or not os.path.exists(kyber_public_path):
                raise CryptoError("Server Kyber keys not found. Run 'python3 keygen_server.py' first.")

            self.dilithium_private = load_key_from_file(dilithium_private_path)
            self.dilithium_public = load_key_from_file(dilithium_public_path)
            self.kyber_private = load_key_from_file(kyber_private_path)
            self.kyber_public = load_key_from_file(kyber_public_path)

            print(f"✓ Loaded server keys from {self.key_dir}")

        except Exception as e:
            print(f"❌ Failed to load server keys: {e}")
            sys.exit(1)

    def _enable_ip_forwarding(self) -> None:
        """Enable IP forwarding and set up iptables"""
        try:
            setup = VPNSetup("tun0")
            if not setup.setup_system():
                print("⚠️  Failed to set up IP forwarding and iptables")
                print("   You may need to run: sudo python3 vpn_setup.py")
        except Exception as e:
            print(f"⚠️  Failed to enable IP forwarding: {e}")

    def _assign_client_ip(self) -> str:
        """Assign an IP address to a new client"""
        # Start from 10.8.0.2, increment until find free IP
        base_ip = "10.8.0."
        for i in range(2, 255):
            ip = f"{base_ip}{i}"
            if ip not in self.assigned_ips:
                self.assigned_ips.add(ip)
                return ip
        raise RuntimeError("No available IP addresses")

    def _release_client_ip(self, ip: str) -> None:
        """Release an assigned IP address"""
        self.assigned_ips.discard(ip)
        if ip in self.ip_to_session:
            del self.ip_to_session[ip]

    def _cleanup_inactive_clients(self) -> None:
        """Clean up inactive clients and release their IPs"""
        current_time = time.time()
        inactive_sessions = []

        for session_id, client in self.clients.items():
            if current_time - client["last_seen"] > CONNECTION_TIMEOUT:
                inactive_sessions.append(session_id)

        for session_id in inactive_sessions:
            client = self.clients[session_id]
            print(f"🧹 {Fore.YELLOW}Cleaning up inactive client{Style.RESET_ALL}: {client['client_id']}")
            self._release_client_ip(client["assigned_ip"])
            del self.clients[session_id]
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n{Fore.YELLOW}Received signal {signum}, shutting down...{Style.RESET_ALL}")
        self.stop()
    
    def start(self) -> None:
        """Start VPN server"""
        if not check_tun_support():
            print(f"❌ TUN interface not supported on this system")
            sys.exit(1)
        
        try:
            # Create TUN interface
            self.tun = TUNInterface("tun0")
            self.tun.configure_ip("10.8.0.1", "255.255.255.0")
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            
            self.running = True
            
            print(f"🚀 {Fore.GREEN}Quantum-Safe VPN Server started{Style.RESET_ALL}")
            print(f"   📡 Listening on {self.host}:{self.port}")
            print(f"   🌐 TUN interface: tun0 (10.8.0.1/24)")
            print(f"   🔐 Post-quantum crypto: Kyber768 + Dilithium3")
            print(f"   ⏰ Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"\n{Fore.CYAN}Waiting for clients...{Style.RESET_ALL}\n")
            
            # Start TUN packet handler
            tun_thread = threading.Thread(target=self._handle_tun_packets, daemon=True)
            tun_thread.start()
            
            # Start statistics reporter
            stats_thread = threading.Thread(target=self._report_stats, daemon=True)
            stats_thread.start()
            
            # Main server loop
            self._server_loop()
            
        except Exception as e:
            print(f"❌ Server startup failed: {e}")
            self.stop()
            sys.exit(1)
    
    def _server_loop(self) -> None:
        """Main server loop - handle UDP messages"""
        while self.running:
            try:
                # Receive UDP message
                data, addr = self.socket.recvfrom(65536)
                validate_message_size(data)
                
                # Process message in separate thread
                threading.Thread(
                    target=self._handle_client_message,
                    args=(data, addr),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"❌ Server loop error: {e}")
                break
    
    def _handle_client_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle message from client"""
        try:
            message = Message.deserialize(data)
            client_id = f"{addr[0]}:{addr[1]}"

            if message.type == MessageType.HANDSHAKE_INIT:
                # Client requesting handshake - send our keys
                self._handle_handshake_init_request(message, addr)

            elif message.type == MessageType.HANDSHAKE_RESPONSE:
                self._handle_handshake_response(message, addr)

            elif message.type == MessageType.DATA_PACKET:
                self._handle_data_packet(message, addr)

            elif message.type == MessageType.KEEPALIVE:
                self._handle_keepalive(message, addr)

            else:
                print(f"⚠️  Unknown message type from {client_id}: {message.type}")

        except ProtocolError as e:
            print(f"❌ Protocol error from {addr}: {e}")
            self._send_error(addr, str(e))
        except Exception as e:
            print(f"❌ Unexpected error handling message from {addr}: {e}")
    
    def _handle_handshake_response(self, message: Message, addr: Tuple[str, int]) -> None:
        """Handle handshake response from client"""
        try:
            # Parse handshake response
            response = HandshakeResponse.deserialize(message.payload)
            client_id = f"{addr[0]}:{addr[1]}"

            print(f"🔄 {Fore.YELLOW}Handshake with {client_id}{Style.RESET_ALL}")

            # Decapsulate Kyber shared secret
            kyber_shared = QuantumSafeCrypto.kyber_decapsulate(
                self.kyber_private, response.kyber_ciphertext
            )

            # Generate ephemeral X25519 keypair
            x25519_public, x25519_private = QuantumSafeCrypto.generate_x25519_keypair()

            # Perform X25519 exchange
            x25519_shared = QuantumSafeCrypto.x25519_exchange(
                x25519_private, response.x25519_pubkey
            )

            # Derive session key
            session_key = QuantumSafeCrypto.derive_session_key(kyber_shared, x25519_shared)

            # Create session crypto
            session_crypto = SessionCrypto(session_key, message.session_id)

            # Assign IP to client
            assigned_ip = self._assign_client_ip()
            self.ip_to_session[assigned_ip] = message.session_id

            # Store client session
            self.clients[message.session_id] = {
                "addr": addr,
                "client_id": client_id,
                "session_crypto": session_crypto,
                "handshake_time": time.time(),
                "last_seen": time.time(),
                "packets_sent": 0,
                "packets_received": 0,
                "client_info": response.client_info,
                "assigned_ip": assigned_ip
            }

            # Send handshake complete with assigned IP and X25519 public key
            x25519_public_bytes = x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            protocol = VPNProtocol(message.session_id)
            complete_msg = protocol.create_handshake_complete(True, "Handshake successful", assigned_ip, x25519_public_bytes)
            self.socket.sendto(complete_msg.serialize(), addr)

            self.stats["handshakes"] += 1

            print(f"✅ {Fore.GREEN}Client {client_id} connected{Style.RESET_ALL}")
            print(f"   📱 Client info: {response.client_info}")
            print(f"   🔑 Session key: {truncate_hex(session_key)}")
            print(f"   🆔 Session ID: {truncate_hex(message.session_id)}")
            print(f"   🌐 Assigned IP: {assigned_ip}")

        except CryptoError as e:
            print(f"❌ Handshake crypto error with {addr}: {e}")
            self._send_error(addr, "Handshake failed")
        except Exception as e:
            print(f"❌ Handshake error with {addr}: {e}")
            self._send_error(addr, "Internal server error")
    
    def _handle_data_packet(self, message: Message, addr: Tuple[str, int]) -> None:
        """Handle encrypted data packet from client"""
        try:
            client = self.clients.get(message.session_id)
            if not client:
                print(f"⚠️  Data packet from unknown session: {addr}")
                return
            
            # Decrypt packet
            ip_packet = client["session_crypto"].decrypt(message.payload)
            
            # Parse and log packet info
            packet_info = parse_ip_packet(ip_packet)
            if "error" not in packet_info:
                print(f"📦 {Fore.BLUE}Packet{Style.RESET_ALL}: {packet_info['src_ip']} -> {packet_info['dst_ip']} ({packet_info['protocol']}, {packet_info['length']} bytes)")
            
            # Forward to TUN interface
            self.tun.write_packet(ip_packet)
            
            # Update statistics
            client["packets_received"] += 1
            client["last_seen"] = time.time()
            self.stats["packets_received"] += 1
            self.stats["bytes_received"] += len(ip_packet)
            
        except CryptoError as e:
            print(f"❌ Decryption error from {addr}: {e}")
        except Exception as e:
            print(f"❌ Data packet error from {addr}: {e}")
    
    def _handle_handshake_init_request(self, message: Message, addr: Tuple[str, int]) -> None:
        """Handle handshake init request from client - send our keys"""
        try:
            client_id = f"{addr[0]}:{addr[1]}"
            print(f"🔄 {Fore.YELLOW}Handshake init request from {client_id}{Style.RESET_ALL}")

            # Create signature of server info (simplified)
            server_info = "quantum-safe-vpn-server"
            signature = QuantumSafeCrypto.dilithium_sign(
                self.dilithium_private, server_info.encode()
            )

            # Send handshake init with our keys
            protocol = VPNProtocol(message.session_id)
            init_msg = protocol.create_handshake_init(
                self.dilithium_public, self.kyber_public, signature
            )
            self.socket.sendto(init_msg.serialize(), addr)

            print(f"📤 {Fore.GREEN}Sent handshake init to {client_id}{Style.RESET_ALL}")

        except Exception as e:
            print(f"❌ Handshake init error with {addr}: {e}")
            self._send_error(addr, "Handshake init failed")

    def _handle_keepalive(self, message: Message, addr: Tuple[str, int]) -> None:
        """Handle keepalive message"""
        client = self.clients.get(message.session_id)
        if client:
            client["last_seen"] = time.time()
            # Send pong back
            protocol = VPNProtocol(message.session_id)
            pong = protocol.create_keepalive()
            self.socket.sendto(pong.serialize(), addr)
    
    def _handle_tun_packets(self) -> None:
        """Handle packets from TUN interface (to be sent to clients)"""
        while self.running:
            try:
                # Read packet from TUN
                ip_packet = self.tun.read_packet()

                # Parse packet to determine destination
                packet_info = parse_ip_packet(ip_packet)
                if "error" in packet_info:
                    continue

                dst_ip = packet_info.get("dst_ip")
                if not dst_ip:
                    continue

                # Check if destination is in VPN subnet
                if dst_ip.startswith("10.8.0."):
                    # Route to specific client
                    session_id = self.ip_to_session.get(dst_ip)
                    if session_id and session_id in self.clients:
                        client = self.clients[session_id]
                        try:
                            # Encrypt packet
                            encrypted_data = client["session_crypto"].encrypt(ip_packet)

                            # Create data message
                            protocol = VPNProtocol(session_id)
                            data_msg = protocol.create_data_packet(encrypted_data)

                            # Send to client
                            self.socket.sendto(data_msg.serialize(), client["addr"])

                            # Update statistics
                            client["packets_sent"] += 1
                            self.stats["packets_sent"] += 1
                            self.stats["bytes_sent"] += len(ip_packet)

                            print(f"📤 {Fore.BLUE}Sent packet{Style.RESET_ALL}: {packet_info['src_ip']} -> {dst_ip} ({packet_info['protocol']}, {packet_info['length']} bytes)")

                        except Exception as e:
                            print(f"❌ Failed to send packet to client {client['client_id']}: {e}")
                    else:
                        print(f"⚠️  No client found for IP {dst_ip}")
                else:
                    # Packet destined for internet - forward through iptables
                    print(f"🌐 {Fore.CYAN}Forwarding packet{Style.RESET_ALL}: {packet_info['src_ip']} -> {dst_ip} ({packet_info['protocol']}, {packet_info['length']} bytes)")

            except Exception as e:
                if self.running:
                    print(f"❌ TUN packet handler error: {e}")
                time.sleep(0.1)
    
    def _send_error(self, addr: Tuple[str, int], error_msg: str) -> None:
        """Send error message to client"""
        try:
            protocol = VPNProtocol()
            error_message = protocol.create_error(error_msg)
            self.socket.sendto(error_message.serialize(), addr)
        except Exception as e:
            print(f"❌ Failed to send error to {addr}: {e}")
    
    def _report_stats(self) -> None:
        """Periodically report server statistics and clean up inactive clients"""
        while self.running:
            time.sleep(30)  # Report every 30 seconds

            # Clean up inactive clients
            self._cleanup_inactive_clients()

            if self.clients:
                uptime = time.time() - self.stats["start_time"]
                print(f"\n📊 {Fore.CYAN}Server Statistics{Style.RESET_ALL}")
                print(f"   ⏰ Uptime: {uptime:.0f}s")
                print(f"   👥 Active clients: {len(self.clients)}")
                print(f"   🤝 Total handshakes: {self.stats['handshakes']}")
                print(f"   📤 Packets sent: {self.stats['packets_sent']}")
                print(f"   📥 Packets received: {self.stats['packets_received']}")
                print(f"   📊 Bytes sent/received: {self.stats['bytes_sent']}/{self.stats['bytes_received']}")
                print()
    
    def stop(self) -> None:
        """Stop VPN server"""
        self.running = False
        
        if self.socket:
            self.socket.close()
        
        if self.tun:
            self.tun.close()
        
        print(f"🛑 {Fore.RED}Server stopped{Style.RESET_ALL}")

@click.command()
@click.option('--host', default='0.0.0.0', help='Server bind address')
@click.option('--port', default=8443, help='Server port')
@click.option('--key-dir', default='keys', help='Directory containing server keys')
def main(host: str, port: int, key_dir: str):
    """Start Quantum-Safe VPN Server"""
    
    print("🛡️  Quantum-Safe VPN Server v1.0")
    print("   Post-Quantum Cryptography Enabled")
    print("=" * 50)
    
    if os.getuid() != 0:
        print("❌ This program requires root privileges for TUN interface access")
        print("   Please run with sudo")
        sys.exit(1)
    
    server = VPNServer(host, port, key_dir)
    server.start()

if __name__ == "__main__":
    main()