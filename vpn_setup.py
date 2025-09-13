#!/usr/bin/env python3
"""
VPN System Setup Utilities
Handles IP forwarding, iptables rules, and system configuration for VPN
"""

import subprocess
import os
import sys
from typing import List, Optional

class VPNSetup:
    """VPN system configuration manager"""

    def __init__(self, tun_interface: str = "tun0", external_interface: str = "eth0"):
        """Initialize VPN setup"""
        self.tun_interface = tun_interface
        self.external_interface = self._detect_external_interface() or external_interface

    def _detect_external_interface(self) -> Optional[str]:
        """Detect the external network interface"""
        try:
            # Get default route interface
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.strip().split('\n')
            if lines:
                parts = lines[0].split()
                if len(parts) >= 5:
                    return parts[4]
        except subprocess.CalledProcessError:
            pass
        return None

    def enable_ip_forwarding(self) -> bool:
        """Enable IPv4 forwarding"""
        try:
            # Enable immediately
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True, capture_output=True
            )

            # Make persistent
            with open("/etc/sysctl.d/99-sysctl.conf", "a") as f:
                f.write("net.ipv4.ip_forward=1\n")

            # Reload sysctl
            subprocess.run(["sysctl", "--system"], check=True, capture_output=True)

            print("✓ IPv4 forwarding enabled")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to enable IP forwarding: {e}")
            return False

    def setup_iptables(self) -> bool:
        """Set up iptables rules for NAT and forwarding"""
        try:
            # Allow forwarding and NAT
            rules = [
                # NAT: Masquerade outgoing traffic
                ["-t", "nat", "-A", "POSTROUTING", "-o", self.external_interface, "-j", "MASQUERADE"],
                # Forward: Allow established and related traffic
                ["-A", "FORWARD", "-i", self.external_interface, "-o", self.tun_interface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                # Forward: Allow traffic from TUN to external
                ["-A", "FORWARD", "-i", self.tun_interface, "-o", self.external_interface, "-j", "ACCEPT"]
            ]

            for rule in rules:
                subprocess.run(["iptables"] + rule, check=True, capture_output=True)

            # Save rules (Ubuntu/Debian)
            try:
                subprocess.run(["iptables-save"], check=True, capture_output=True)
                print("✓ iptables rules configured")
            except subprocess.CalledProcessError:
                print("⚠️  iptables-save failed, rules may not persist after reboot")
                print("   Install iptables-persistent: sudo apt-get install -y iptables-persistent")

            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to set up iptables: {e}")
            return False

    def cleanup_iptables(self) -> bool:
        """Clean up iptables rules"""
        try:
            # Remove NAT rule
            subprocess.run([
                "iptables", "-t", "nat", "-D", "POSTROUTING",
                "-o", self.external_interface, "-j", "MASQUERADE"
            ], capture_output=True)

            # Remove forward rules
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-i", self.external_interface, "-o", self.tun_interface,
                "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], capture_output=True)

            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-i", self.tun_interface, "-o", self.external_interface, "-j", "ACCEPT"
            ], capture_output=True)

            print("✓ iptables rules cleaned up")
            return True
        except subprocess.CalledProcessError:
            return False

    def setup_system(self) -> bool:
        """Complete system setup for VPN"""
        print("🔧 Setting up VPN system configuration...")

        success = True
        success &= self.enable_ip_forwarding()
        success &= self.setup_iptables()

        if success:
            print("✅ VPN system setup complete")
        else:
            print("❌ VPN system setup failed")

        return success

    def cleanup_system(self) -> bool:
        """Clean up system configuration"""
        print("🧹 Cleaning up VPN system configuration...")

        success = True
        success &= self.cleanup_iptables()

        if success:
            print("✅ VPN system cleanup complete")
        else:
            print("❌ VPN system cleanup failed")

        return success

def main():
    """Command-line interface for VPN setup"""
    if os.getuid() != 0:
        print("❌ This script requires root privileges")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="VPN System Setup")
    parser.add_argument("--tun", default="tun0", help="TUN interface name")
    parser.add_argument("--external", help="External interface name")
    parser.add_argument("--cleanup", action="store_true", help="Clean up configuration")

    args = parser.parse_args()

    setup = VPNSetup(args.tun, args.external or "eth0")

    if args.cleanup:
        setup.cleanup_system()
    else:
        setup.setup_system()

if __name__ == "__main__":
    main()
