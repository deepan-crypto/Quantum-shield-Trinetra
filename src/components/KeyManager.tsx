import React, { useState } from 'react';
import { Key, Plus, Trash2, RefreshCw, Download, Upload, Shield, AlertCircle, CheckCircle } from 'lucide-react';
import { KeyPair } from '../types';

const KeyManager: React.FC = () => {
  const [keys, setKeys] = useState<KeyPair[]>([
    {
      id: '1',
      type: 'dilithium',
      purpose: 'server',
      algorithm: 'CRYSTALS-Dilithium3',
      createdAt: Date.now() - 86400000, // 1 day ago
      fingerprint: 'a1b2c3d4e5f67890',
      status: 'active'
    },
    {
      id: '2',
      type: 'kyber',
      purpose: 'server',
      algorithm: 'CRYSTALS-Kyber768',
      createdAt: Date.now() - 86400000,
      fingerprint: 'f1e2d3c4b5a69870',
      status: 'active'
    },
    {
      id: '3',
      type: 'dilithium',
      purpose: 'client',
      algorithm: 'CRYSTALS-Dilithium3',
      createdAt: Date.now() - 3600000, // 1 hour ago
      fingerprint: '9876543210abcdef',
      status: 'active'
    }
  ]);

  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  const getKeyTypeColor = (type: KeyPair['type']) => {
    switch (type) {
      case 'kyber': return 'bg-quantum-100 text-quantum-700';
      case 'dilithium': return 'bg-purple-100 text-purple-700';
      case 'x25519': return 'bg-blue-100 text-blue-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  };

  const getStatusColor = (status: KeyPair['status']) => {
    switch (status) {
      case 'active': return 'status-connected';
      case 'expired': return 'status-disconnected';
      case 'revoked': return 'status-disconnected';
      default: return 'status-disconnected';
    }
  };

  const handleGenerateKeys = async () => {
    setIsGenerating(true);
    // Simulate key generation
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const newKey: KeyPair = {
      id: Date.now().toString(),
      type: 'dilithium',
      purpose: 'server',
      algorithm: 'CRYSTALS-Dilithium3',
      createdAt: Date.now(),
      fingerprint: Math.random().toString(16).substr(2, 16),
      status: 'active'
    };
    
    setKeys(prev => [...prev, newKey]);
    setIsGenerating(false);
    setShowGenerateModal(false);
  };

  const handleDeleteKey = (keyId: string) => {
    setKeys(prev => prev.filter(key => key.id !== keyId));
  };

  const handleRevokeKey = (keyId: string) => {
    setKeys(prev => prev.map(key => 
      key.id === keyId ? { ...key, status: 'revoked' as const } : key
    ));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Key Manager</h2>
          <p className="text-gray-600">Manage cryptographic keys for quantum-safe VPN</p>
        </div>
        <div className="flex items-center space-x-3">
          <button className="btn-secondary">
            <Upload className="w-4 h-4 mr-2" />
            Import Keys
          </button>
          <button 
            onClick={() => setShowGenerateModal(true)}
            className="btn-primary"
          >
            <Plus className="w-4 h-4 mr-2" />
            Generate Keys
          </button>
        </div>
      </div>

      {/* Key Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Keys</p>
              <p className="text-3xl font-bold text-gray-900">{keys.length}</p>
            </div>
            <Key className="w-8 h-8 text-quantum-600" />
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Keys</p>
              <p className="text-3xl font-bold text-crypto-600">
                {keys.filter(k => k.status === 'active').length}
              </p>
            </div>
            <CheckCircle className="w-8 h-8 text-crypto-600" />
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Server Keys</p>
              <p className="text-3xl font-bold text-blue-600">
                {keys.filter(k => k.purpose === 'server').length}
              </p>
            </div>
            <Shield className="w-8 h-8 text-blue-600" />
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Client Keys</p>
              <p className="text-3xl font-bold text-purple-600">
                {keys.filter(k => k.purpose === 'client').length}
              </p>
            </div>
            <Key className="w-8 h-8 text-purple-600" />
          </div>
        </div>
      </div>

      {/* Keys List */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Cryptographic Keys</h3>
          <button className="btn-secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>

        <div className="space-y-4">
          {keys.map((key) => (
            <div key={key.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-quantum-100 rounded-full flex items-center justify-center">
                    <Key className="w-6 h-6 text-quantum-600" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-3 mb-1">
                      <h4 className="font-medium text-gray-900">{key.algorithm}</h4>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getKeyTypeColor(key.type)}`}>
                        {key.type.toUpperCase()}
                      </span>
                      <span className={`status-indicator ${getStatusColor(key.status)}`}>
                        {key.status === 'active' && (
                          <div className="w-2 h-2 bg-crypto-500 rounded-full mr-2 animate-pulse"></div>
                        )}
                        {key.status}
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      <span>Purpose: {key.purpose}</span>
                      <span>•</span>
                      <span>Fingerprint: {key.fingerprint}</span>
                      <span>•</span>
                      <span>Created: {formatDate(key.createdAt)}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-gray-400 hover:text-blue-600 transition-colors">
                    <Download className="w-4 h-4" />
                  </button>
                  {key.status === 'active' && (
                    <button 
                      onClick={() => handleRevokeKey(key.id)}
                      className="p-2 text-gray-400 hover:text-yellow-600 transition-colors"
                    >
                      <AlertCircle className="w-4 h-4" />
                    </button>
                  )}
                  <button 
                    onClick={() => handleDeleteKey(key.id)}
                    className="p-2 text-gray-400 hover:text-red-600 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Generation Guidelines */}
      <div className="card bg-blue-50 border-blue-200">
        <div className="flex items-start space-x-3">
          <Shield className="w-6 h-6 text-blue-600 mt-1" />
          <div>
            <h3 className="font-semibold text-blue-800 mb-2">Key Management Best Practices</h3>
            <ul className="text-blue-700 text-sm space-y-1">
              <li>• Generate new keys regularly (recommended: every 90 days)</li>
              <li>• Store private keys securely with proper access controls</li>
              <li>• Use different key pairs for different purposes (server vs client)</li>
              <li>• Backup keys in encrypted storage before deployment</li>
              <li>• Revoke compromised keys immediately</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Generate Keys Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Generate New Keys</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Key Type</label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-quantum-500">
                  <option value="dilithium">CRYSTALS-Dilithium3 (Signatures)</option>
                  <option value="kyber">CRYSTALS-Kyber768 (Key Exchange)</option>
                  <option value="x25519">X25519 (Classical ECDH)</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Purpose</label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-quantum-500">
                  <option value="server">Server Authentication</option>
                  <option value="client">Client Authentication</option>
                </select>
              </div>
            </div>
            
            <div className="flex items-center justify-end space-x-3 mt-6">
              <button 
                onClick={() => setShowGenerateModal(false)}
                className="btn-secondary"
                disabled={isGenerating}
              >
                Cancel
              </button>
              <button 
                onClick={handleGenerateKeys}
                className="btn-primary"
                disabled={isGenerating}
              >
                {isGenerating ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Key className="w-4 h-4 mr-2" />
                    Generate Keys
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default KeyManager;