export interface VPNConnection {
  id: string;
  clientId: string;
  status: 'connected' | 'connecting' | 'disconnected';
  connectedAt: number;
  lastSeen: number;
  sessionId: string;
  clientInfo: string;
  bytesTransferred: number;
  packetsTransferred: number;
  tunnelIP: string;
}

export interface TrafficData {
  timestamp: number;
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
}

export interface CryptoInfo {
  kemAlgorithm: string;
  signatureAlgorithm: string;
  sessionEncryption: string;
  keyDerivation: string;
  isQuantumSafe: boolean;
}

export interface KeyPair {
  id: string;
  type: 'kyber' | 'dilithium' | 'x25519';
  purpose: 'server' | 'client';
  algorithm: string;
  createdAt: number;
  fingerprint: string;
  status: 'active' | 'expired' | 'revoked';
}