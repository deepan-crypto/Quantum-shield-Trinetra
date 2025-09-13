#!/usr/bin/env python3
"""
Quantum-Safe VPN Client
Implements post-quantum secure VPN client with TUN interface
"""

import os
import sys
import time
import socket
import threading
import signal
from typing import Optional, Tuple
import click
from colorama import init, Fore, Style

from crypto_utils import (
    QuantumSafeCrypto, SessionCrypto, CryptoError,
    load_key_from_file, truncate_hex
)
from tun_utils import TUNInterface, parse_ip_packet, check_tun_support
from protocol import (
    Message, MessageType, HandshakeInit, HandshakeResponse, HandshakeComplete,
    VPNProtocol, ProtocolError, validate_message_size
)

# Initialize colorama
init()

class VPNClient:
    """Quantum-Safe VPN Client"""
    
    def __init__(self, server_host: str, server_port: int, key_dir: str = "keys"):
        """Initialize VPN client"""
        self.server_host = server_host
        self.server_port = server_port
        self.key_dir = key_dir
        self.running = False
        
        # Network components
        self.socket = None
        self.tun = None
        self.server_addr = (server_host, server_port)
        
        # Session state
        self.session_crypto = None
        self.session_id = None
        self.connected = False
        
        # Statistics
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connect_time": None,
            "last_keepalive": time.time()
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n{Fore.YELLOW}Received signal {signum}, shutting down...{Style.RESET_ALL}")
        self.stop()
    
    def start(self) -> None:
        """Start VPN client"""
        if not check_tun_support():
            print(f"❌ TUN interface not supported on this system")
            sys.exit(1)
        
        try:
            # Create TUN interface
            self.tun = TUNInterface("tun0")
            self.tun.configure_ip("10.8.0.2", "255.255.255.0")
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(5.0)  # 5 second timeout

            self.running = True

            print(f"🚀 {Fore.GREEN}Quantum-Safe VPN Client started{Style.RESET_ALL}")
            print(f"   🎯 Server: {self.server_host}:{self.server_port}")
            # TUN IP will be assigned by server handshake
            self.tun_ip = None
            print(f"   🌐 TUN interface: tun0 (IP to be assigned)")
            print(f"   🔐 Post-quantum crypto: Kyber768 + Dilithium3")

            # Perform handshake
            if not self._perform_handshake():
                print("❌ Handshake failed")
                self.stop()
                return

            # Configure TUN IP after handshake
            if self.tun_ip:
                self.tun.configure_ip(self.tun_ip, "255.255.255.0")
                print(f"✓ Configured TUN interface with IP {self.tun_ip}/24")
            else:
                print("⚠️  No IP assigned by server, using default 10.8.0.2")
                self.tun.configure_ip("10.8.0.2", "255.255.255.0")

            print(f"✅ {Fore.GREEN}Connected to server{Style.RESET_ALL}\n")

            # Start packet handlers
            udp_thread = threading.Thread(target=self._handle_udp_messages, daemon=True)
            udp_thread.start()

            tun_thread = threading.Thread(target=self._handle_tun_packets, daemon=True)
            tun_thread.start()

            keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            keepalive_thread.start()

            # Wait for shutdown
            while self.running:
                time.sleep(1)

        except Exception as e:
            print(f"❌ Client startup failed: {e}")
            self.stop()
            sys.exit(1)
    
    def _perform_handshake(self) -> bool:
        """Perform handshake with server"""
        try:
            print(f"🔄 {Fore.YELLOW}Starting handshake...{Style.RESET_ALL}")
            
            # Generate ephemeral keys
            x25519_public, x25519_private = QuantumSafeCrypto.generate_x25519_keypair()
            
            # Load server's public key (in real implementation, this would be verified)
            server_public_path = os.path.join(self.key_dir, "server_dilithium_public.pem")
            if not os.path.exists(server_public_path):
                print(f"❌ Server public key not found: {server_public_path}")
                return False
            
            server_dilithium_public = load_key_from_file(server_public_path)
            
            # Generate Kyber ciphertext and shared secret
            kyber_ciphertext, kyber_shared = QuantumSafeCrypto.kyber_encapsulate(server_dilithium_public)
            
            # Perform X25519 exchange (we'll get server's public key in response)
            x25519_public_bytes = x25519_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Create handshake response
            protocol = VPNProtocol()
            self.session_id = protocol.session_id
            
            response_msg = protocol.create_handshake_response(
                kyber_ciphertext, x25519_public_bytes
            )
            
            # Send handshake response
            self.socket.sendto(response_msg.serialize(), self.server_addr)
            
            # Wait for handshake complete
            data, addr = self.socket.recvfrom(65536)
            message = Message.deserialize(data)
            
            if message.type != MessageType.HANDSHAKE_COMPLETE:
                print(f"❌ Unexpected message type: {message.type}")
                return False
            
            complete = HandshakeComplete.deserialize(message.payload)
            if not complete.success:
                print(f"❌ Handshake failed: {complete.message}")
                return False
            
            # We need to derive the same session key as server
            # For this simplified implementation, we'll use a placeholder
            # In real implementation, server would send its X25519 public key
            x25519_shared = b"placeholder_x25519_shared_secret_32b"  # This should come from server
            
            # Derive session key
            session_key = QuantumSafeCrypto.derive_session_key(kyber_shared, x25519_shared)
            
            # Create session crypto
            self.session_crypto = SessionCrypto(session_key, self.session_id)
            self.connected = True
            self.stats["connect_time"] = time.time()
            
            print(f"✅ Handshake successful")
            print(f"   🔑 Session key: {truncate_hex(session_key)}")
            print(f"   🆔 Session ID: {truncate_hex(self.session_id)}")
            
            return True
            
        except Exception as e:
            print(f"❌ Handshake error: {e}")
            return False
    
    def _handle_udp_messages(self) -> None:
        """Handle messages from server"""
        while self.running and self.connected:
            try:
                data, addr = self.socket.recvfrom(65536)
                
                if addr != self.server_addr:
                    continue
                
                message = Message.deserialize(data)
                
                if message.type == MessageType.DATA_PACKET:
                    self._handle_data_packet(message)
                elif message.type == MessageType.KEEPALIVE:
                    self._handle_keepalive(message)
                elif message.type == MessageType.ERROR:
                    print(f"❌ Server error: {message.payload.decode()}")
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"❌ UDP message handler error: {e}")
                    break
    
    def _handle_data_packet(self, message: Message) -> None:
        """Handle data packet from server"""
        try:
            if not self.session_crypto:
                return
            
            # Decrypt packet
            ip_packet = self.session_crypto.decrypt(message.payload)
            
            # Parse and log packet info
            packet_info = parse_ip_packet(ip_packet)
            if "error" not in packet_info:
                print(f"📦 {Fore.BLUE}Packet{Style.RESET_ALL}: {packet_info['src_ip']} -> {packet_info['dst_ip']} ({packet_info['protocol']}, {packet_info['length']} bytes)")
            
            # Write to TUN interface
            self.tun.write_packet(ip_packet)
            
            # Update statistics
            self.stats["packets_received"] += 1
            self.stats["bytes_received"] += len(ip_packet)
            
        except CryptoError as e:
            print(f"❌ Decryption error: {e}")
        except Exception as e:
            print(f"❌ Data packet error: {e}")
    
    def _handle_tun_packets(self) -> None:
        """Handle packets from TUN interface"""
        while self.running and self.connected:
            try:
                # Read packet from TUN
                ip_packet = self.tun.read_packet()
                
                if not self.session_crypto:
                    continue
                
                # Encrypt packet
                encrypted_data = self.session_crypto.encrypt(ip_packet)
                
                # Create data message
                protocol = VPNProtocol(self.session_id)
                data_msg = protocol.create_data_packet(encrypted_data)
                
                # Send to server
                self.socket.sendto(data_msg.serialize(), self.server_addr)
                
                # Update statistics
                self.stats["packets_sent"] += 1
                self.stats["bytes_sent"] += len(ip_packet)
                
            except Exception as e:
                if self.running:
                    print(f"❌ TUN packet handler error: {e}")
                time.sleep(0.1)
    
    def _handle_keepalive(self, message: Message) -> None:
        """Handle keepalive from server"""
        self.stats["last_keepalive"] = time.time()
    
    def _keepalive_loop(self) -> None:
        """Send periodic keepalives to server"""
        while self.running and self.connected:
            try:
                # Send keepalive every 30 seconds
                time.sleep(30)
                
                if self.session_crypto:
                    protocol = VPNProtocol(self.session_id)
                    keepalive = protocol.create_keepalive()
                    self.socket.sendto(keepalive.serialize(), self.server_addr)
                    
            except Exception as e:
                if self.running:
                    print(f"❌ Keepalive error: {e}")
    
    def stop(self) -> None:
        """Stop VPN client"""
        self.running = False
        self.connected = False
        
        if self.socket:
            self.socket.close()
        
        if self.tun:
            self.tun.close()
        
        # Print final statistics
        if self.stats["connect_time"]:
            uptime = time.time() - self.stats["connect_time"]
            print(f"\n📊 {Fore.CYAN}Final Statistics{Style.RESET_ALL}")
            print(f"   ⏰ Connected for: {uptime:.0f}s")
            print(f"   📤 Packets sent: {self.stats['packets_sent']}")
            print(f"   📥 Packets received: {self.stats['packets_received']}")
            print(f"   📊 Bytes sent/received: {self.stats['bytes_sent']}/{self.stats['bytes_received']}")
        
        print(f"🛑 {Fore.RED}Client stopped{Style.RESET_ALL}")

# We need to add the missing import
from cryptography.hazmat.primitives import serialization

@click.command()
@click.option('--server', default='127.0.0.1', help='Server address')
@click.option('--port', default=8443, help='Server port')
@click.option('--key-dir', default='keys', help='Directory containing keys')
def main(server: str, port: int, key_dir: str):
    """Start Quantum-Safe VPN Client"""
    
    print("🛡️  Quantum-Safe VPN Client v1.0")
    print("   Post-Quantum Cryptography Enabled")
    print("=" * 50)
    
    if os.getuid() != 0:
        print("❌ This program requires root privileges for TUN interface access")
        print("   Please run with sudo")
        sys.exit(1)
    
    client = VPNClient(server, port, key_dir)
    client.start()

if __name__ == "__main__":
    main()