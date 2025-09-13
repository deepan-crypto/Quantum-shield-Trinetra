import React from 'react';
import { Shield, Lock, Key, CheckCircle, AlertTriangle, Zap } from 'lucide-react';
import { CryptoInfo } from '../types';

interface CryptoStatusProps {
  cryptoInfo: CryptoInfo;
}

const CryptoStatus: React.FC<CryptoStatusProps> = ({ cryptoInfo }) => {
  const algorithms = [
    {
      name: 'Key Encapsulation',
      algorithm: cryptoInfo.kemAlgorithm,
      description: 'Post-quantum key exchange mechanism',
      status: 'active',
      icon: Key,
      color: 'quantum',
      details: 'CRYSTALS-Kyber is a lattice-based KEM selected by NIST for standardization. It provides security against both classical and quantum attacks.'
    },
    {
      name: 'Digital Signatures',
      algorithm: cryptoInfo.signatureAlgorithm,
      description: 'Post-quantum authentication',
      status: 'active',
      icon: Shield,
      color: 'purple',
      details: 'CRYSTALS-Dilithium is a lattice-based signature scheme that ensures authenticity and non-repudiation in a post-quantum world.'
    },
    {
      name: 'Session Encryption',
      algorithm: cryptoInfo.sessionEncryption,
      description: 'Symmetric encryption for data',
      status: 'active',
      icon: Lock,
      color: 'crypto',
      details: 'AES-256-GCM provides authenticated encryption with 256-bit keys derived from the post-quantum key exchange.'
    },
    {
      name: 'Key Derivation',
      algorithm: cryptoInfo.keyDerivation,
      description: 'Secure key generation',
      status: 'active',
      icon: Zap,
      color: 'blue',
      details: 'HKDF-SHA256 derives cryptographic keys from the shared secrets established by both Kyber and X25519 key exchanges.'
    }
  ];

  const getColorClasses = (color: string) => {
    const colors = {
      quantum: 'bg-quantum-100 text-quantum-700 border-quantum-200',
      purple: 'bg-purple-100 text-purple-700 border-purple-200',
      crypto: 'bg-crypto-100 text-crypto-700 border-crypto-200',
      blue: 'bg-blue-100 text-blue-700 border-blue-200'
    };
    return colors[color as keyof typeof colors] || colors.blue;
  };

  const getIconColorClasses = (color: string) => {
    const colors = {
      quantum: 'text-quantum-600',
      purple: 'text-purple-600',
      crypto: 'text-crypto-600',
      blue: 'text-blue-600'
    };
    return colors[color as keyof typeof colors] || colors.blue;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Cryptographic Status</h2>
          <p className="text-gray-600">Monitor post-quantum cryptographic algorithms and security status</p>
        </div>
        <div className="flex items-center space-x-2">
          <CheckCircle className="w-5 h-5 text-crypto-500" />
          <span className="text-sm font-medium text-crypto-700">All Systems Secure</span>
        </div>
      </div>

      {/* Quantum-Safe Status Banner */}
      <div className="card bg-gradient-to-r from-quantum-50 via-purple-50 to-crypto-50 border-quantum-200">
        <div className="flex items-center space-x-4">
          <div className="p-4 bg-white rounded-full shadow-sm">
            <Shield className="w-10 h-10 text-quantum-600" />
          </div>
          <div className="flex-1">
            <div className="flex items-center space-x-2 mb-2">
              <h3 className="text-xl font-bold text-gray-900">Quantum-Safe Protection</h3>
              <div className="px-3 py-1 bg-crypto-100 text-crypto-700 rounded-full text-sm font-medium">
                ACTIVE
              </div>
            </div>
            <p className="text-gray-600 mb-3">
              Your VPN is protected against both classical and quantum computer attacks using 
              NIST-standardized post-quantum cryptographic algorithms.
            </p>
            <div className="flex items-center space-x-6 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-crypto-500 rounded-full animate-pulse"></div>
                <span className="text-crypto-700">Post-Quantum KEM Active</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-purple-500 rounded-full animate-pulse"></div>
                <span className="text-purple-700">Post-Quantum Signatures Active</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Algorithm Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {algorithms.map((algo, index) => {
          const Icon = algo.icon;
          return (
            <div key={index} className="card">
              <div className="flex items-start space-x-4">
                <div className={`p-3 rounded-full ${getColorClasses(algo.color)}`}>
                  <Icon className={`w-6 h-6 ${getIconColorClasses(algo.color)}`} />
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-semibold text-gray-900">{algo.name}</h3>
                    <div className="flex items-center space-x-1">
                      <CheckCircle className="w-4 h-4 text-crypto-500" />
                      <span className="text-xs font-medium text-crypto-600 uppercase">Active</span>
                    </div>
                  </div>
                  <p className="text-lg font-mono text-gray-800 mb-2">{algo.algorithm}</p>
                  <p className="text-sm text-gray-600 mb-3">{algo.description}</p>
                  <p className="text-xs text-gray-500 leading-relaxed">{algo.details}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Security Metrics */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-6">Security Metrics</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="w-16 h-16 bg-quantum-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <Shield className="w-8 h-8 text-quantum-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Key Security Level</h4>
            <p className="text-2xl font-bold text-quantum-600 mb-1">256-bit</p>
            <p className="text-sm text-gray-500">Equivalent classical security</p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <Lock className="w-8 h-8 text-purple-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Quantum Resistance</h4>
            <p className="text-2xl font-bold text-purple-600 mb-1">NIST Level 3</p>
            <p className="text-sm text-gray-500">Post-quantum security level</p>
          </div>
          
          <div className="text-center">
            <div className="w-16 h-16 bg-crypto-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <Zap className="w-8 h-8 text-crypto-600" />
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Performance</h4>
            <p className="text-2xl font-bold text-crypto-600 mb-1">Optimized</p>
            <p className="text-sm text-gray-500">Hardware-accelerated when available</p>
          </div>
        </div>
      </div>

      {/* Algorithm Comparison */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-6">Classical vs Post-Quantum</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-medium text-gray-900">Component</th>
                <th className="text-left py-3 px-4 font-medium text-gray-900">Classical Algorithm</th>
                <th className="text-left py-3 px-4 font-medium text-gray-900">Post-Quantum Algorithm</th>
                <th className="text-left py-3 px-4 font-medium text-gray-900">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              <tr>
                <td className="py-3 px-4 font-medium text-gray-900">Key Exchange</td>
                <td className="py-3 px-4 text-gray-600">X25519 (ECDH)</td>
                <td className="py-3 px-4 text-gray-600">CRYSTALS-Kyber768</td>
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-1">
                    <CheckCircle className="w-4 h-4 text-crypto-500" />
                    <span className="text-sm text-crypto-600">Hybrid</span>
                  </div>
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-gray-900">Signatures</td>
                <td className="py-3 px-4 text-gray-600">Ed25519</td>
                <td className="py-3 px-4 text-gray-600">CRYSTALS-Dilithium3</td>
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-1">
                    <CheckCircle className="w-4 h-4 text-purple-500" />
                    <span className="text-sm text-purple-600">Post-Quantum</span>
                  </div>
                </td>
              </tr>
              <tr>
                <td className="py-3 px-4 font-medium text-gray-900">Encryption</td>
                <td className="py-3 px-4 text-gray-600">AES-256-GCM</td>
                <td className="py-3 px-4 text-gray-600">AES-256-GCM</td>
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-1">
                    <CheckCircle className="w-4 h-4 text-blue-500" />
                    <span className="text-sm text-blue-600">Quantum-Safe</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Assessment */}
      <div className="card bg-yellow-50 border-yellow-200">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-6 h-6 text-yellow-600 mt-1" />
          <div>
            <h3 className="font-semibold text-yellow-800 mb-2">Quantum Threat Timeline</h3>
            <p className="text-yellow-700 text-sm mb-3">
              While large-scale quantum computers capable of breaking current cryptography don't exist yet, 
              experts estimate they could emerge within 10-30 years. This VPN is already prepared for that future.
            </p>
            <div className="text-xs text-yellow-600">
              <strong>Recommendation:</strong> Continue using post-quantum algorithms to ensure long-term security.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CryptoStatus;