import React, { useState } from 'react';
import { Users, Plus, Trash2, Eye, EyeOff, RefreshCw, AlertCircle } from 'lucide-react';
import { VPNConnection } from '../types';

interface ConnectionManagerProps {
  connections: VPNConnection[];
  setConnections: React.Dispatch<React.SetStateAction<VPNConnection[]>>;
}

const ConnectionManager: React.FC<ConnectionManagerProps> = ({ connections, setConnections }) => {
  const [showDetails, setShowDetails] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDuration = (timestamp: number) => {
    const duration = Date.now() - timestamp;
    const hours = Math.floor(duration / (1000 * 60 * 60));
    const minutes = Math.floor((duration % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((duration % (1000 * 60)) / 1000);
    return `${hours}h ${minutes}m ${seconds}s`;
  };

  const handleDisconnect = (connectionId: string) => {
    setConnections(prev => prev.map(conn => 
      conn.id === connectionId 
        ? { ...conn, status: 'disconnected' as const }
        : conn
    ));
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsRefreshing(false);
  };

  const getStatusColor = (status: VPNConnection['status']) => {
    switch (status) {
      case 'connected': return 'status-connected';
      case 'connecting': return 'status-connecting';
      case 'disconnected': return 'status-disconnected';
      default: return 'status-disconnected';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Connection Manager</h2>
          <p className="text-gray-600">Manage and monitor VPN client connections</p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button className="btn-primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Client
          </button>
        </div>
      </div>

      {/* Connection Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Connections</p>
              <p className="text-3xl font-bold text-gray-900">{connections.length}</p>
            </div>
            <Users className="w-8 h-8 text-quantum-600" />
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Connections</p>
              <p className="text-3xl font-bold text-crypto-600">
                {connections.filter(c => c.status === 'connected').length}
              </p>
            </div>
            <div className="w-8 h-8 bg-crypto-100 rounded-full flex items-center justify-center">
              <div className="w-4 h-4 bg-crypto-500 rounded-full animate-pulse"></div>
            </div>
          </div>
        </div>
        
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Data</p>
              <p className="text-3xl font-bold text-blue-600">
                {formatBytes(connections.reduce((sum, conn) => sum + conn.bytesTransferred, 0))}
              </p>
            </div>
            <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
              <div className="w-4 h-4 bg-blue-500 rounded-full"></div>
            </div>
          </div>
        </div>
      </div>

      {/* Connections Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Client Connections</h3>
          <div className="text-sm text-gray-500">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>

        {connections.length === 0 ? (
          <div className="text-center py-12">
            <Users className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No connections</h3>
            <p className="text-gray-500 mb-6">No clients are currently connected to the VPN server.</p>
            <button className="btn-primary">
              <Plus className="w-4 h-4 mr-2" />
              Add First Client
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {connections.map((connection) => (
              <div key={connection.id} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-12 h-12 bg-quantum-100 rounded-full flex items-center justify-center">
                      <Users className="w-6 h-6 text-quantum-600" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-3">
                        <h4 className="font-medium text-gray-900">{connection.clientId}</h4>
                        <span className={`status-indicator ${getStatusColor(connection.status)}`}>
                          {connection.status === 'connected' && (
                            <div className="w-2 h-2 bg-crypto-500 rounded-full mr-2 animate-pulse"></div>
                          )}
                          {connection.status}
                        </span>
                      </div>
                      <div className="flex items-center space-x-4 text-sm text-gray-500 mt-1">
                        <span>Tunnel IP: {connection.tunnelIP}</span>
                        <span>•</span>
                        <span>Session: {connection.sessionId}</span>
                        <span>•</span>
                        <span>Connected: {formatDuration(connection.connectedAt)}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <div className="text-right text-sm">
                      <div className="font-medium text-gray-900">
                        {formatBytes(connection.bytesTransferred)}
                      </div>
                      <div className="text-gray-500">
                        {connection.packetsTransferred.toLocaleString()} packets
                      </div>
                    </div>
                    
                    <button
                      onClick={() => setShowDetails(showDetails === connection.id ? null : connection.id)}
                      className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      {showDetails === connection.id ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                    
                    {connection.status === 'connected' && (
                      <button
                        onClick={() => handleDisconnect(connection.id)}
                        className="p-2 text-red-400 hover:text-red-600 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Connection Details */}
                {showDetails === connection.id && (
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      <div>
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Client Info</p>
                        <p className="mt-1 text-sm text-gray-900">{connection.clientInfo}</p>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Last Seen</p>
                        <p className="mt-1 text-sm text-gray-900">
                          {new Date(connection.lastSeen).toLocaleString()}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Session ID</p>
                        <p className="mt-1 text-sm text-gray-900 font-mono">{connection.sessionId}</p>
                      </div>
                      <div>
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Encryption</p>
                        <p className="mt-1 text-sm text-gray-900">AES-256-GCM</p>
                      </div>
                    </div>
                    
                    <div className="mt-4 p-3 bg-quantum-50 rounded-lg border border-quantum-200">
                      <div className="flex items-center space-x-2">
                        <AlertCircle className="w-4 h-4 text-quantum-600" />
                        <span className="text-sm font-medium text-quantum-700">Quantum-Safe Connection</span>
                      </div>
                      <p className="mt-1 text-sm text-quantum-600">
                        This connection is secured with post-quantum cryptographic algorithms 
                        (CRYSTALS-Kyber768 + CRYSTALS-Dilithium3) and is resistant to quantum computer attacks.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ConnectionManager;