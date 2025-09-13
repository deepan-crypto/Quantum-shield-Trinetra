#!/usr/bin/env python3
"""
Protocol definitions for Quantum-Safe VPN
Defines message formats and handshake protocol
"""

import struct
import json
import os
from enum import IntEnum
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

class MessageType(IntEnum):
    """Message types for VPN protocol"""
    HANDSHAKE_INIT = 1      # Server -> Client: Dilithium pubkey + signature
    HANDSHAKE_RESPONSE = 2  # Client -> Server: Kyber ciphertext + X25519 pubkey
    HANDSHAKE_COMPLETE = 3  # Server -> Client: Handshake complete
    DATA_PACKET = 4         # Encrypted tunnel data
    KEEPALIVE = 5          # Keep connection alive
    ERROR = 255            # Error message

class ProtocolError(Exception):
    """Protocol-related errors"""
    pass

class Message:
    """VPN protocol message"""
    
    def __init__(self, msg_type: MessageType, payload: bytes = b"", session_id: bytes = b""):
        """Create protocol message"""
        self.type = msg_type
        self.payload = payload
        self.session_id = session_id or os.urandom(16)
        self.length = len(payload)
    
    def serialize(self) -> bytes:
        """Serialize message to bytes
        Format: [1-byte type][4-byte length][16-byte session_id][payload]
        """
        header = struct.pack("!BI16s", self.type, self.length, self.session_id)
        return header + self.payload
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Message':
        """Deserialize message from bytes"""
        if len(data) < 21:  # 1 + 4 + 16
            raise ProtocolError("Message too short")
        
        msg_type, length, session_id = struct.unpack("!BI16s", data[:21])
        
        if len(data) != 21 + length:
            raise ProtocolError(f"Invalid message length: expected {21 + length}, got {len(data)}")
        
        payload = data[21:21 + length]
        return cls(MessageType(msg_type), payload, session_id)
    
    def __repr__(self) -> str:
        return f"Message(type={self.type.name}, length={self.length}, session_id={self.session_id.hex()[:8]}...)"

class HandshakeInit:
    """Handshake initialization message (server -> client)"""
    
    def __init__(self, dilithium_pubkey: bytes, signature: bytes, server_info: str = "quantum-safe-vpn"):
        self.dilithium_pubkey = dilithium_pubkey
        self.signature = signature
        self.server_info = server_info
    
    def serialize(self) -> bytes:
        """Serialize handshake init"""
        data = {
            "dilithium_pubkey": self.dilithium_pubkey.hex(),
            "signature": self.signature.hex(),
            "server_info": self.server_info
        }
        return json.dumps(data).encode()
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'HandshakeInit':
        """Deserialize handshake init"""
        try:
            obj = json.loads(data.decode())
            return cls(
                dilithium_pubkey=bytes.fromhex(obj["dilithium_pubkey"]),
                signature=bytes.fromhex(obj["signature"]),
                server_info=obj.get("server_info", "unknown")
            )
        except Exception as e:
            raise ProtocolError(f"Invalid handshake init: {e}")

class HandshakeResponse:
    """Handshake response message (client -> server)"""
    
    def __init__(self, kyber_ciphertext: bytes, x25519_pubkey: bytes, client_info: str = "quantum-safe-client"):
        self.kyber_ciphertext = kyber_ciphertext
        self.x25519_pubkey = x25519_pubkey
        self.client_info = client_info
    
    def serialize(self) -> bytes:
        """Serialize handshake response"""
        data = {
            "kyber_ciphertext": self.kyber_ciphertext.hex(),
            "x25519_pubkey": self.x25519_pubkey.hex(),
            "client_info": self.client_info
        }
        return json.dumps(data).encode()
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'HandshakeResponse':
        """Deserialize handshake response"""
        try:
            obj = json.loads(data.decode())
            return cls(
                kyber_ciphertext=bytes.fromhex(obj["kyber_ciphertext"]),
                x25519_pubkey=bytes.fromhex(obj["x25519_pubkey"]),
                client_info=obj.get("client_info", "unknown")
            )
        except Exception as e:
            raise ProtocolError(f"Invalid handshake response: {e}")

class HandshakeComplete:
    """Handshake complete message (server -> client)"""

    def __init__(self, success: bool = True, message: str = "Handshake successful", assigned_ip: str = None):
        self.success = success
        self.message = message
        self.assigned_ip = assigned_ip

    def serialize(self) -> bytes:
        """Serialize handshake complete"""
        data = {
            "success": self.success,
            "message": self.message
        }
        if self.assigned_ip:
            data["assigned_ip"] = self.assigned_ip
        return json.dumps(data).encode()

    @classmethod
    def deserialize(cls, data: bytes) -> 'HandshakeComplete':
        """Deserialize handshake complete"""
        try:
            obj = json.loads(data.decode())
            return cls(
                success=obj.get("success", False),
                message=obj.get("message", "Unknown status"),
                assigned_ip=obj.get("assigned_ip")
            )
        except Exception as e:
            raise ProtocolError(f"Invalid handshake complete: {e}")

class DataPacket:
    """Encrypted data packet"""
    
    def __init__(self, encrypted_data: bytes):
        self.encrypted_data = encrypted_data
        self.length = len(encrypted_data)
    
    def serialize(self) -> bytes:
        """Serialize data packet"""
        return self.encrypted_data
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'DataPacket':
        """Deserialize data packet"""
        return cls(data)

class VPNProtocol:
    """High-level VPN protocol handler"""
    
    def __init__(self, session_id: Optional[bytes] = None):
        self.session_id = session_id or os.urandom(16)
    
    def create_handshake_init(self, dilithium_pubkey: bytes, signature: bytes) -> Message:
        """Create handshake init message"""
        handshake = HandshakeInit(dilithium_pubkey, signature)
        return Message(MessageType.HANDSHAKE_INIT, handshake.serialize(), self.session_id)
    
    def create_handshake_response(self, kyber_ciphertext: bytes, x25519_pubkey: bytes) -> Message:
        """Create handshake response message"""
        handshake = HandshakeResponse(kyber_ciphertext, x25519_pubkey)
        return Message(MessageType.HANDSHAKE_RESPONSE, handshake.serialize(), self.session_id)
    
    def create_handshake_complete(self, success: bool = True, message: str = "OK") -> Message:
        """Create handshake complete message"""
        handshake = HandshakeComplete(success, message)
        return Message(MessageType.HANDSHAKE_COMPLETE, handshake.serialize(), self.session_id)
    
    def create_data_packet(self, encrypted_data: bytes) -> Message:
        """Create data packet message"""
        packet = DataPacket(encrypted_data)
        return Message(MessageType.DATA_PACKET, packet.serialize(), self.session_id)
    
    def create_keepalive(self) -> Message:
        """Create keepalive message"""
        return Message(MessageType.KEEPALIVE, b"ping", self.session_id)
    
    def create_error(self, error_message: str) -> Message:
        """Create error message"""
        payload = json.dumps({"error": error_message}).encode()
        return Message(MessageType.ERROR, payload, self.session_id)

# Protocol constants
MAX_MESSAGE_SIZE = 65535    # 64KB max message
HANDSHAKE_TIMEOUT = 30      # 30 seconds
KEEPALIVE_INTERVAL = 60     # 1 minute
CONNECTION_TIMEOUT = 300    # 5 minutes

def validate_message_size(data: bytes) -> None:
    """Validate message size"""
    if len(data) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"Message too large: {len(data)} > {MAX_MESSAGE_SIZE}")

def format_session_id(session_id: bytes) -> str:
    """Format session ID for display"""
    return session_id.hex()[:8] + "..."

if __name__ == "__main__":
    # Test protocol message serialization
    print("Testing VPN protocol...")
    
    # Test basic message
    msg = Message(MessageType.KEEPALIVE, b"test payload")
    serialized = msg.serialize()
    deserialized = Message.deserialize(serialized)
    
    print(f"Original: {msg}")
    print(f"Deserialized: {deserialized}")
    print(f"Payloads match: {msg.payload == deserialized.payload}")
    
    # Test handshake messages
    protocol = VPNProtocol()
    init_msg = protocol.create_handshake_init(b"dummy_pubkey", b"dummy_signature")
    
    print(f"Handshake init: {init_msg}")
    print("✓ Protocol test successful")