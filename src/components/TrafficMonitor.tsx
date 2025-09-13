import React, { useState } from 'react';
import { Activity, TrendingUp, TrendingDown, BarChart3, PieChart } from 'lucide-react';
import { TrafficData } from '../types';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar } from 'recharts';

interface TrafficMonitorProps {
  trafficData: TrafficData[];
}

const TrafficMonitor: React.FC<TrafficMonitorProps> = ({ trafficData }) => {
  const [chartType, setChartType] = useState<'line' | 'area' | 'bar'>('line');
  const [timeRange, setTimeRange] = useState<'1m' | '5m' | '15m'>('1m');

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatPackets = (packets: number) => {
    if (packets >= 1000) {
      return (packets / 1000).toFixed(1) + 'K';
    }
    return packets.toString();
  };

  // Calculate statistics
  const totalBytesIn = trafficData.reduce((sum, data) => sum + data.bytesIn, 0);
  const totalBytesOut = trafficData.reduce((sum, data) => sum + data.bytesOut, 0);
  const totalPacketsIn = trafficData.reduce((sum, data) => sum + data.packetsIn, 0);
  const totalPacketsOut = trafficData.reduce((sum, data) => sum + data.packetsOut, 0);

  const avgBytesIn = trafficData.length > 0 ? totalBytesIn / trafficData.length : 0;
  const avgBytesOut = trafficData.length > 0 ? totalBytesOut / trafficData.length : 0;

  // Prepare chart data
  const chartData = trafficData.map(data => ({
    time: new Date(data.timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    }),
    'Bytes In': data.bytesIn,
    'Bytes Out': data.bytesOut,
    'Packets In': data.packetsIn,
    'Packets Out': data.packetsOut,
    'Total Bytes': data.bytesIn + data.bytesOut,
    'Total Packets': data.packetsIn + data.packetsOut
  }));

  const renderChart = () => {
    const commonProps = {
      data: chartData,
      margin: { top: 5, right: 30, left: 20, bottom: 5 }
    };

    switch (chartType) {
      case 'area':
        return (
          <AreaChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} />
            <YAxis stroke="#6b7280" fontSize={12} tickLine={false} tickFormatter={formatBytes} />
            <Tooltip 
              contentStyle={{
                backgroundColor: 'white',
                border: '1px solid #e5e7eb',
                borderRadius: '8px',
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
              }}
              formatter={(value: number) => [formatBytes(value), '']}
            />
            <Area 
              type="monotone" 
              dataKey="Bytes In" 
              stackId="1"
              stroke="#3b82f6" 
              fill="#3b82f6"
              fillOpacity={0.6}
            />
            <Area 
              type="monotone" 
              dataKey="Bytes Out" 
              stackId="1"
              stroke="#22c55e" 
              fill="#22c55e"
              fillOpacity={0.6}
            />
          </AreaChart>
        );
      
      case 'bar':
        return (
          <BarChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} />
            <YAxis stroke="#6b7280" fontSize={12} tickLine={false} tickFormatter={formatBytes} />
            <Tooltip 
              contentStyle={{
                backgroundColor: 'white',
                border: '1px solid #e5e7eb',
                borderRadius: '8px',
                boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
              }}
              formatter={(value: number) => [formatBytes(value), '']}
            />
            <Bar dataKey="Bytes In" fill="#3b82f6" />
            <Bar dataKey="Bytes Out" fill="#22c55e" />
          </BarChart>
        );
      
      default:
        return (
          <LineChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} />
            <YAxis stroke="#6b7280" fontSize={12} tickLine={false} tickFormatter={formatBytes} />
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
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Traffic Monitor</h2>
          <p className="text-gray-600">Real-time network traffic analysis and monitoring</p>
        </div>
        <div className="flex items-center space-x-3">
          <select 
            value={timeRange} 
            onChange={(e) => setTimeRange(e.target.value as '1m' | '5m' | '15m')}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-quantum-500"
          >
            <option value="1m">Last 1 minute</option>
            <option value="5m">Last 5 minutes</option>
            <option value="15m">Last 15 minutes</option>
          </select>
          <div className="flex items-center space-x-1 bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setChartType('line')}
              className={`p-2 rounded ${chartType === 'line' ? 'bg-white shadow-sm' : ''}`}
            >
              <Activity className="w-4 h-4" />
            </button>
            <button
              onClick={() => setChartType('area')}
              className={`p-2 rounded ${chartType === 'area' ? 'bg-white shadow-sm' : ''}`}
            >
              <PieChart className="w-4 h-4" />
            </button>
            <button
              onClick={() => setChartType('bar')}
              className={`p-2 rounded ${chartType === 'bar' ? 'bg-white shadow-sm' : ''}`}
            >
              <BarChart3 className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Traffic Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Bytes In</p>
              <p className="text-2xl font-bold text-quantum-600">{formatBytes(totalBytesIn)}</p>
            </div>
            <div className="p-3 bg-quantum-100 rounded-full">
              <TrendingDown className="w-6 h-6 text-quantum-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            Avg: {formatBytes(avgBytesIn)}/s
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Bytes Out</p>
              <p className="text-2xl font-bold text-crypto-600">{formatBytes(totalBytesOut)}</p>
            </div>
            <div className="p-3 bg-crypto-100 rounded-full">
              <TrendingUp className="w-6 h-6 text-crypto-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            Avg: {formatBytes(avgBytesOut)}/s
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Packets In</p>
              <p className="text-2xl font-bold text-blue-600">{formatPackets(totalPacketsIn)}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-full">
              <Activity className="w-6 h-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            Total packets received
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Packets Out</p>
              <p className="text-2xl font-bold text-purple-600">{formatPackets(totalPacketsOut)}</p>
            </div>
            <div className="p-3 bg-purple-100 rounded-full">
              <Activity className="w-6 h-6 text-purple-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            Total packets sent
          </div>
        </div>
      </div>

      {/* Traffic Chart */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900">Real-time Traffic Flow</h3>
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
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            {renderChart()}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Packet Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Packet Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={12} tickLine={false} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="Packets In" 
                  stackId="1"
                  stroke="#3b82f6" 
                  fill="#3b82f6"
                  fillOpacity={0.6}
                />
                <Area 
                  type="monotone" 
                  dataKey="Packets Out" 
                  stackId="1"
                  stroke="#22c55e" 
                  fill="#22c55e"
                  fillOpacity={0.6}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Traffic Summary</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 bg-quantum-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-4 h-4 bg-quantum-500 rounded-full"></div>
                <span className="font-medium text-gray-900">Inbound Traffic</span>
              </div>
              <div className="text-right">
                <div className="font-bold text-quantum-600">{formatBytes(totalBytesIn)}</div>
                <div className="text-sm text-gray-500">{totalPacketsIn.toLocaleString()} packets</div>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-crypto-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-4 h-4 bg-crypto-500 rounded-full"></div>
                <span className="font-medium text-gray-900">Outbound Traffic</span>
              </div>
              <div className="text-right">
                <div className="font-bold text-crypto-600">{formatBytes(totalBytesOut)}</div>
                <div className="text-sm text-gray-500">{totalPacketsOut.toLocaleString()} packets</div>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-4 h-4 bg-gray-500 rounded-full"></div>
                <span className="font-medium text-gray-900">Total Traffic</span>
              </div>
              <div className="text-right">
                <div className="font-bold text-gray-900">{formatBytes(totalBytesIn + totalBytesOut)}</div>
                <div className="text-sm text-gray-500">{(totalPacketsIn + totalPacketsOut).toLocaleString()} packets</div>
              </div>
            </div>

            <div className="pt-4 border-t border-gray-200">
              <div className="text-sm text-gray-600">
                <div className="flex justify-between mb-1">
                  <span>Average throughput:</span>
                  <span className="font-medium">{formatBytes(avgBytesIn + avgBytesOut)}/s</span>
                </div>
                <div className="flex justify-between">
                  <span>Data points:</span>
                  <span className="font-medium">{trafficData.length}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TrafficMonitor;