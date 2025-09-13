import React from 'react';
import { Shield, Users, Activity, Zap, TrendingUp, Clock, Network, Lock } from 'lucide-react';
import { VPNConnection, TrafficData, CryptoInfo } from '../types';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface DashboardProps {
  connections: VPNConnection[];
  trafficData: TrafficData[];
  cryptoInfo: CryptoInfo;
}

const Dashboard: React.FC<DashboardProps> = ({ connections, trafficData, cryptoInfo }) => {
  const activeConnections = connections.filter(conn => conn.status === 'connected').length;
  const totalBytesTransferred = connections.reduce((sum, conn) => sum + conn.bytesTransferred, 0);
  const totalPacketsTransferred = connections.reduce((sum, conn) => sum + conn.packetsTransferred, 0);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatUptime = (timestamp: number) => {
    const uptime = Date.now() - timestamp;
    const hours = Math.floor(uptime / (1000 * 60 * 60));
    const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${minutes}m`;
  };

  const chartData = trafficData.map(data => ({
    time: new Date(data.timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    }),
    'Bytes In': data.bytesIn,
    'Bytes Out': data.bytesOut
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">VPN Dashboard</h2>
          <p className="text-gray-600">Monitor your quantum-safe VPN connections and traffic</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-crypto-500 rounded-full animate-pulse"></div>
          <span className="text-sm font-medium text-crypto-700">Quantum-Safe Active</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Connections</p>
              <p className="text-3xl font-bold text-gray-900">{activeConnections}</p>
            </div>
            <div className="p-3 bg-quantum-100 rounded-full">
              <Users className="w-6 h-6 text-quantum-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <TrendingUp className="w-4 h-4 text-crypto-500 mr-1" />
            <span className="text-crypto-600">All connections secure</span>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Data Transferred</p>
              <p className="text-3xl font-bold text-gray-900">{formatBytes(totalBytesTransferred)}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-full">
              <Activity className="w-6 h-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <Network className="w-4 h-4 text-blue-500 mr-1" />
            <span className="text-blue-600">{totalPacketsTransferred.toLocaleString()} packets</span>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Crypto Algorithm</p>
              <p className="text-lg font-bold text-gray-900">Kyber768</p>
            </div>
            <div className="p-3 bg-purple-100 rounded-full">
              <Shield className="w-6 h-6 text-purple-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <Lock className="w-4 h-4 text-purple-500 mr-1" />
            <span className="text-purple-600">Post-Quantum Safe</span>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Server Uptime</p>
              <p className="text-3xl font-bold text-gray-900">
                {connections.length > 0 ? formatUptime(connections[0].connectedAt) : '0h 0m'}
              </p>
            </div>
            <div className="p-3 bg-green-100 rounded-full">
              <Clock className="w-6 h-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center text-sm">
            <Zap className="w-4 h-4 text-green-500 mr-1" />
            <span className="text-green-600">Stable connection</span>
          </div>
        </div>
      </div>

      {/* Traffic Chart */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Real-time Traffic</h3>
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center">
              <div className="w-3 h-3 bg-quantum-500 rounded-full mr-2"></div>
              <span>Bytes In</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 bg-crypto-500 rounded-full mr-2"></div>
              <span>Bytes Out</span>
            </div>
          </div>
        </div>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis 
                dataKey="time" 
                stroke="#6b7280"
                fontSize={12}
                tickLine={false}
              />
              <YAxis 
                stroke="#6b7280"
                fontSize={12}
                tickLine={false}
                tickFormatter={formatBytes}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'white',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                }}
                formatter={(value: number) => [formatBytes(value), '']}
              />
              <Line 
                type="monotone" 
                dataKey="Bytes In" 
                stroke="#3b82f6" 
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, fill: '#3b82f6' }}
              />
              <Line 
                type="monotone" 
                dataKey="Bytes Out" 
                stroke="#22c55e" 
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4, fill: '#22c55e' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Active Connections */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Active Connections</h3>
        <div className="space-y-4">
          {connections.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <Users className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p>No active connections</p>
            </div>
          ) : (
            connections.map((connection) => (
              <div key={connection.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="w-10 h-10 bg-quantum-100 rounded-full flex items-center justify-center">
                    <Shield className="w-5 h-5 text-quantum-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">{connection.clientId}</p>
                    <p className="text-sm text-gray-500">
                      Tunnel IP: {connection.tunnelIP} • Session: {connection.sessionId}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="status-indicator status-connected mb-2">
                    <div className="w-2 h-2 bg-crypto-500 rounded-full mr-2 animate-pulse"></div>
                    Connected
                  </div>
                  <p className="text-sm text-gray-500">
                    {formatBytes(connection.bytesTransferred)} transferred
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Quantum-Safe Status */}
      <div className="card bg-gradient-to-r from-quantum-50 to-crypto-50 border-quantum-200">
        <div className="flex items-center space-x-4">
          <div className="p-3 bg-white rounded-full shadow-sm">
            <Shield className="w-8 h-8 text-quantum-600" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-gray-900">Quantum-Safe Protection Active</h3>
            <p className="text-gray-600">
              Your VPN is protected against both classical and quantum computer attacks using 
              post-quantum cryptographic algorithms.
            </p>
          </div>
          <div className="text-right">
            <div className="flex items-center text-sm text-crypto-700 mb-1">
              <Zap className="w-4 h-4 mr-1" />
              <span>CRYSTALS-Kyber768</span>
            </div>
            <div className="flex items-center text-sm text-purple-700">
              <Lock className="w-4 h-4 mr-1" />
              <span>CRYSTALS-Dilithium3</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;