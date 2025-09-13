import React, { useState, useEffect } from 'react';
import { Shield, Activity, Users, Settings, Key, Network, Zap } from 'lucide-react';
import Dashboard from './components/Dashboard';
import ConnectionManager from './components/ConnectionManager';
import CryptoStatus from './components/CryptoStatus';
import TrafficMonitor from './components/TrafficMonitor';
import KeyManager from './components/KeyManager';
import { VPNConnection, TrafficData, CryptoInfo } from './types';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [connections, setConnections] = useState<VPNConnection[]>([]);
  const [trafficData, setTrafficData] = useState<TrafficData[]>([]);
  const [cryptoInfo, setCryptoInfo] = useState<CryptoInfo>({
    kemAlgorithm: 'CRYSTALS-Kyber768',
    signatureAlgorithm: 'CRYSTALS-Dilithium3',
    sessionEncryption: 'AES-256-GCM',
    keyDerivation: 'HKDF-SHA256',
    isQuantumSafe: true
  });

  // Simulate real-time data updates
  useEffect(() => {
    const interval = setInterval(() => {
      // Update traffic data
      const now = Date.now();
      setTrafficData(prev => {
        const newData = {
          timestamp: now,
          bytesIn: Math.floor(Math.random() * 1000) + 500,
          bytesOut: Math.floor(Math.random() * 800) + 300,
          packetsIn: Math.floor(Math.random() * 50) + 20,
          packetsOut: Math.floor(Math.random() * 40) + 15
        };
        return [...prev.slice(-29), newData]; // Keep last 30 data points
      });

      // Update connection status
      setConnections(prev => prev.map(conn => ({
        ...conn,
        lastSeen: now,
        bytesTransferred: conn.bytesTransferred + Math.floor(Math.random() * 1000)
      })));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // Initialize with sample data
  useEffect(() => {
    const sampleConnection: VPNConnection = {
      id: '1',
      clientId: '192.168.1.100:54321',
      status: 'connected',
      connectedAt: Date.now() - 300000, // 5 minutes ago
      lastSeen: Date.now(),
      sessionId: 'a1b2c3d4e5f6',
      clientInfo: 'quantum-safe-client',
      bytesTransferred: 1024000,
      packetsTransferred: 2500,
      tunnelIP: '10.8.0.2'
    };

    setConnections([sampleConnection]);

    // Initialize traffic data
    const initialTrafficData: TrafficData[] = [];
    const now = Date.now();
    for (let i = 29; i >= 0; i--) {
      initialTrafficData.push({
        timestamp: now - (i * 2000),
        bytesIn: Math.floor(Math.random() * 1000) + 500,
        bytesOut: Math.floor(Math.random() * 800) + 300,
        packetsIn: Math.floor(Math.random() * 50) + 20,
        packetsOut: Math.floor(Math.random() * 40) + 15
      });
    }
    setTrafficData(initialTrafficData);
  }, []);

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'connections', label: 'Connections', icon: Users },
    { id: 'crypto', label: 'Crypto Status', icon: Shield },
    { id: 'traffic', label: 'Traffic Monitor', icon: Network },
    { id: 'keys', label: 'Key Manager', icon: Key },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard connections={connections} trafficData={trafficData} cryptoInfo={cryptoInfo} />;
      case 'connections':
        return <ConnectionManager connections={connections} setConnections={setConnections} />;
      case 'crypto':
        return <CryptoStatus cryptoInfo={cryptoInfo} />;
      case 'traffic':
        return <TrafficMonitor trafficData={trafficData} />;
      case 'keys':
        return <KeyManager />;
      default:
        return <Dashboard connections={connections} trafficData={trafficData} cryptoInfo={cryptoInfo} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-quantum-600" />
                <Zap className="w-4 h-4 text-crypto-500 absolute -top-1 -right-1 animate-pulse" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">Quantum-Safe VPN</h1>
                <p className="text-sm text-gray-500">Post-Quantum Cryptography Enabled</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="status-indicator status-connected">
                <div className="w-2 h-2 bg-crypto-500 rounded-full mr-2 animate-pulse"></div>
                Quantum-Safe
              </div>
              <button className="btn-secondary">
                <Settings className="w-4 h-4 mr-2" />
                Settings
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex space-x-8">
          {/* Sidebar Navigation */}
          <nav className="w-64 space-y-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-left transition-colors duration-200 ${
                    activeTab === tab.id
                      ? 'bg-quantum-100 text-quantum-700 border border-quantum-200'
                      : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Main Content */}
          <main className="flex-1">
            {renderContent()}
          </main>
        </div>
      </div>
    </div>
  );
}

export default App;