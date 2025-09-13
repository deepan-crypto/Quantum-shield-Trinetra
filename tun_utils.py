#!/usr/bin/env python3
"""
TUN interface utilities for Linux
Handles TUN device creation and packet I/O
"""

import os
import struct
import fcntl
import socket
import subprocess
from typing import Optional

# TUN/TAP constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class TUNInterface:
    """Linux TUN interface wrapper"""
    
    def __init__(self, name: str = "tun0"):
        """Create TUN interface"""
        self.name = name
        self.fd = None
        self._create_tun()
    
    def _create_tun(self) -> None:
        """Create TUN device"""
        try:
            # Open TUN device
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # Create interface
            ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            
            print(f"✓ Created TUN interface: {self.name}")
            
        except Exception as e:
            if self.fd:
                os.close(self.fd)
            raise RuntimeError(f"Failed to create TUN interface: {e}")
    
    def configure_ip(self, ip_address: str, netmask: str = "255.255.255.0") -> None:
        """Configure IP address on TUN interface"""
        try:
            # Bring interface up and configure IP
            subprocess.run([
                "ip", "addr", "add", f"{ip_address}/24", "dev", self.name
            ], check=True, capture_output=True)
            
            subprocess.run([
                "ip", "link", "set", "dev", self.name, "up"
            ], check=True, capture_output=True)
            
            print(f"✓ Configured {self.name} with IP {ip_address}/24")
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to configure TUN interface: {e.stderr.decode()}")
    
    def read_packet(self) -> bytes:
        """Read IP packet from TUN interface"""
        try:
            return os.read(self.fd, 4096)
        except Exception as e:
            raise RuntimeError(f"Failed to read from TUN: {e}")
    
    def write_packet(self, packet: bytes) -> None:
        """Write IP packet to TUN interface"""
        try:
            os.write(self.fd, packet)
        except Exception as e:
            raise RuntimeError(f"Failed to write to TUN: {e}")
    
    def close(self) -> None:
        """Close TUN interface"""
        if self.fd:
            os.close(self.fd)
            self.fd = None
        
        # Remove interface
        try:
            subprocess.run([
                "ip", "link", "delete", self.name
            ], check=True, capture_output=True)
            print(f"✓ Removed TUN interface: {self.name}")
        except subprocess.CalledProcessError:
            pass  # Interface might already be gone
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def parse_ip_packet(packet: bytes) -> dict:
    """Parse basic IP packet information"""
    if len(packet) < 20:
        return {"error": "Packet too short"}
    
    try:
        # Parse IP header (simplified)
        version_ihl = packet[0]
        version = (version_ihl >> 4) & 0xF
        ihl = (version_ihl & 0xF) * 4
        
        if version != 4:
            return {"error": f"Unsupported IP version: {version}"}
        
        protocol = packet[9]
        src_ip = socket.inet_ntoa(packet[12:16])
        dst_ip = socket.inet_ntoa(packet[16:20])
        
        protocol_names = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP"
        }
        
        return {
            "version": version,
            "protocol": protocol_names.get(protocol, f"Unknown({protocol})"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "length": len(packet)
        }
    except Exception as e:
        return {"error": f"Parse error: {e}"}

def check_tun_support() -> bool:
    """Check if TUN is supported on this system"""
    try:
        return os.path.exists("/dev/net/tun")
    except:
        return False

if __name__ == "__main__":
    # Test TUN interface creation
    if not check_tun_support():
        print("❌ TUN not supported on this system")
        exit(1)
    
    print("Testing TUN interface...")
    try:
        with TUNInterface("test-tun") as tun:
            tun.configure_ip("192.168.100.1")
            print("✓ TUN interface test successful")
    except Exception as e:
        print(f"❌ TUN interface test failed: {e}")