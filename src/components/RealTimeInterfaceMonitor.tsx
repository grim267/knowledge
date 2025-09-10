import React, { useState, useEffect } from 'react';
import { Wifi, Feather as Ethernet, Activity, Shield, Brain, AlertTriangle, Play, Square, RefreshCw } from 'lucide-react';

interface InterfaceStats {
  name: string;
  type: 'wifi' | 'ethernet';
  packets: number;
  threats: number;
  bytes: number;
  threat_rate: number;
  active: boolean;
  protocol_distribution: Record<string, number>;
  threat_types: Record<string, number>;
}

interface MonitoringStats {
  total_packets: number;
  total_threats: number;
  total_blocked_ips: number;
  interfaces: Record<string, InterfaceStats>;
  monitoring_active: boolean;
  model_info: {
    model_status: string;
    feature_count: number;
    cache_size: number;
    training_data_available: number;
  };
}

interface RealtimeThreat {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  interface: string;
  interface_type: string;
  threat_type: string;
  severity: number;
  confidence: number;
  description: string;
  protocol: string;
}

export function RealTimeInterfaceMonitor() {
  const [stats, setStats] = useState<MonitoringStats | null>(null);
  const [recentThreats, setRecentThreats] = useState<RealtimeThreat[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [monitoringLog, setMonitoringLog] = useState<string[]>([]);
  const [availableInterfaces, setAvailableInterfaces] = useState<Array<{name: string, type: string, is_up: boolean}>>([]);

  const monitorApiUrl = 'http://localhost:8005'; // Real-time monitor API

  useEffect(() => {
    checkMonitorConnection();
    fetchAvailableInterfaces();
    
    // Set up periodic stats refresh
    const statsInterval = setInterval(() => {
      if (isConnected) {
        fetchMonitoringStats();
        fetchRecentThreats();
      }
    }, 5000);

    return () => {
      clearInterval(statsInterval);
    };
  }, [isConnected]);

  const checkMonitorConnection = async () => {
    try {
      const response = await fetch(`${monitorApiUrl}/api/health`);
      if (response.ok) {
        const health = await response.json();
        setIsConnected(true);
        setIsMonitoring(health.monitoring_active || false);
        addToLog('✅ Connected to real-time interface monitor');
      } else {
        setIsConnected(false);
        addToLog('❌ Real-time monitor not responding');
      }
    } catch (error) {
      setIsConnected(false);
      addToLog('❌ Failed to connect to real-time monitor');
      addToLog('💡 Start with: python real_time_interface_monitor.py');
    }
  };

  const fetchAvailableInterfaces = async () => {
    try {
      const response = await fetch(`${monitorApiUrl}/api/interfaces`);
      if (response.ok) {
        const data = await response.json();
        if (data && Array.isArray(data.interfaces)) {
          setAvailableInterfaces(data.interfaces);
          addToLog(`📡 Found ${data.interfaces.length} network interfaces`);
        }
      }
    } catch (error) {
      console.error('Failed to fetch interfaces:', error);
      setAvailableInterfaces([]);
    }
  };

  const fetchMonitoringStats = async () => {
    try {
      const response = await fetch(`${monitorApiUrl}/api/stats`);
      if (response.ok) {
        const monitoringStats = await response.json();
        // Validate and sanitize stats data
        if (monitoringStats && typeof monitoringStats === 'object' && monitoringStats.interfaces) {
          // Ensure interfaces object exists and is valid
          const validatedStats = {
            ...monitoringStats,
            interfaces: monitoringStats.interfaces || {},
            total_packets: monitoringStats.total_packets || 0,
            total_threats: monitoringStats.total_threats || 0,
            total_blocked_ips: monitoringStats.total_blocked_ips || 0,
            monitoring_active: monitoringStats.monitoring_active || false,
            model_info: monitoringStats.model_info || {
              model_status: 'unknown',
              feature_count: 0,
              cache_size: 0,
              training_data_available: 0
            }
          };
          setStats(monitoringStats);
        } else {
          // Set default stats if invalid data received
          setStats({
            total_packets: 0,
            total_threats: 0,
            total_blocked_ips: 0,
            interfaces: {},
            monitoring_active: false,
            model_info: {
              model_status: 'not_loaded',
              feature_count: 0,
              cache_size: 0,
              training_data_available: 0
            }
          });
        }
      } else {
        addToLog('❌ Failed to fetch monitoring stats');
      }
    } catch (error) {
      console.error('Failed to fetch monitoring stats:', error);
      addToLog('❌ Failed to fetch monitoring stats');
      // Set safe default stats on error
      setStats({
        total_packets: 0,
        total_threats: 0,
        total_blocked_ips: 0,
        interfaces: {},
        monitoring_active: false,
        model_info: {
          model_status: 'error',
          feature_count: 0,
          cache_size: 0,
          training_data_available: 0
        }
      });
    }
  };

  const fetchRecentThreats = async () => {
    try {
      const response = await fetch(`${monitorApiUrl}/api/threats/recent?limit=20`);
      if (response.ok) {
        const threats = await response.json();
        // Validate and filter threats data
        if (threats && threats.threats && Array.isArray(threats.threats)) {
          // Filter out invalid threats
          const validThreats = threats.threats.filter(threat => 
            threat && 
            threat.id && 
            threat.timestamp && 
            threat.source_ip &&
            typeof threat.severity === 'number' &&
            typeof threat.confidence === 'number'
          );
          setRecentThreats(threats.threats);
        } else {
          addToLog('⚠️ Invalid threat data received');
          setRecentThreats([]);
        }
      } else {
        addToLog('❌ Failed to fetch recent threats');
        setRecentThreats([]);
      }
    } catch (error) {
      console.error('Failed to fetch recent threats:', error);
      setRecentThreats([]);
    }
  };

  const startMonitoring = async () => {
    if (!isConnected) {
      addToLog('❌ Cannot start monitoring - not connected to monitor API');
      return;
    }

    try {
      addToLog('🚀 Starting real-time interface monitoring...');
      const response = await fetch(`${monitorApiUrl}/api/start`, {
        method: 'POST'
      });
      
      if (response.ok) {
        const result = await response.json();
        setIsMonitoring(true);
        addToLog(`✅ Monitoring started: ${result.message || 'Success'}`);
        // Immediately fetch stats after starting
        setTimeout(() => {
          fetchMonitoringStats();
          fetchRecentThreats();
        }, 1000);
      } else {
        const errorData = await response.text();
        addToLog(`❌ Failed to start monitoring: ${errorData}`);
      }
    } catch (error) {
      addToLog(`❌ Error starting monitoring: ${error}`);
    }
  };

  const stopMonitoring = async () => {
    try {
      addToLog('🛑 Stopping real-time interface monitoring...');
      const response = await fetch(`${monitorApiUrl}/api/stop`, {
        method: 'POST'
      });
      
      if (response.ok) {
        setIsMonitoring(false);
        addToLog('✅ Monitoring stopped successfully');
      } else {
        const errorData = await response.text();
        addToLog(`❌ Failed to stop monitoring: ${errorData}`);
      }
    } catch (error) {
      addToLog(`❌ Error stopping monitoring: ${error}`);
    }
  };

  const addToLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setMonitoringLog(prev => [`[${timestamp}] ${message}`, ...prev.slice(0, 49)]);
  };

  const getInterfaceIcon = (type: string) => {
    return type === 'wifi' ? <Wifi className="h-5 w-5" /> : <Ethernet className="h-5 w-5" />;
  };

  const getSeverityColor = (severity: number) => {
    if (severity >= 8) return 'text-red-400';
    if (severity >= 6) return 'text-orange-400';
    if (severity >= 4) return 'text-yellow-400';
    return 'text-blue-400';
  };

  const getThreatTypeColor = (threatType: string) => {
    switch (threatType) {
      case 'malware': return 'bg-red-900/30 text-red-300';
      case 'ddos': return 'bg-orange-900/30 text-orange-300';
      case 'port_scan': return 'bg-yellow-900/30 text-yellow-300';
      case 'brute_force': return 'bg-purple-900/30 text-purple-300';
      default: return 'bg-gray-900/30 text-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white flex items-center">
            <Activity className="h-6 w-6 text-green-400 mr-2" />
            Real-Time Interface Monitoring
          </h2>
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
              <span className="text-sm text-gray-300">
                Monitor {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <button
              onClick={checkMonitorConnection}
              className="p-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
            >
              <RefreshCw className="h-4 w-4 text-white" />
            </button>
            <button
              onClick={isMonitoring ? stopMonitoring : startMonitoring}
              disabled={!isConnected}
              className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center space-x-2 ${
                isMonitoring 
                  ? 'bg-red-600 hover:bg-red-700 text-white' 
                  : 'bg-green-600 hover:bg-green-700 text-white'
              } disabled:bg-gray-600 disabled:cursor-not-allowed`}
            >
              {isMonitoring ? <Square className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              <span>{isMonitoring ? 'Stop' : 'Start'} Monitoring</span>
            </button>
          </div>
        </div>

        {/* Connection Warning */}
        {!isConnected && (
          <div className="bg-red-900/30 border border-red-700/50 rounded-lg p-4 mb-6">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-red-300 font-medium">Real-Time Monitor Not Connected</p>
                <p className="text-red-400 text-sm">Start the monitor: <code>python real_time_interface_monitor.py</code></p>
                <p className="text-red-400 text-xs">Note: Requires administrator/root privileges for packet capture</p>
              </div>
            </div>
          </div>
        )}

        {/* Overall Statistics */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-blue-400 text-2xl font-bold">{stats.total_packets.toLocaleString()}</div>
              <div className="text-gray-400 text-sm">Total Packets</div>
            </div>
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-red-400 text-2xl font-bold">{stats.total_threats}</div>
              <div className="text-gray-400 text-sm">Threats Detected</div>
            </div>
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-orange-400 text-2xl font-bold">{stats.total_blocked_ips}</div>
              <div className="text-gray-400 text-sm">Blocked IPs</div>
            </div>
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-green-400 text-2xl font-bold">
                {stats.interfaces ? Object.keys(stats.interfaces).filter(i => stats.interfaces[i]?.active).length : 0}
              </div>
              <div className="text-gray-400 text-sm">Active Interfaces</div>
            </div>
          </div>
        )}

        {/* Model Status */}
        {stats && stats.model_info && (
          <div className="bg-purple-900/20 border border-purple-700/50 rounded-lg p-4">
            <h4 className="text-purple-300 font-medium mb-2">ML Model Status</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-gray-400">Status:</span>
                <span className="text-white ml-1">{stats.model_info.model_status}</span>
              </div>
              <div>
                <span className="text-gray-400">Features:</span>
                <span className="text-white ml-1">{stats.model_info.feature_count}</span>
              </div>
              <div>
                <span className="text-gray-400">Cache:</span>
                <span className="text-white ml-1">{stats.model_info.cache_size} predictions</span>
              </div>
              <div>
                <span className="text-gray-400">Learning:</span>
                <span className="text-white ml-1">{stats.model_info.training_data_available} new samples</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Interface Status */}
      {stats && stats.interfaces && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-4">Network Interfaces</h3>
          
          {Object.keys(stats.interfaces).length === 0 ? (
            <div className="text-center py-8">
              <Activity className="h-12 w-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-400">No network interfaces detected</p>
              <p className="text-gray-500 text-sm">Start the real-time monitor to detect interfaces</p>
              {availableInterfaces.length > 0 && (
                <div className="mt-4">
                  <p className="text-gray-400 text-sm">Available interfaces:</p>
                  <div className="flex flex-wrap justify-center gap-2 mt-2">
                    {availableInterfaces.map(iface => (
                      <span key={iface.name} className="text-xs px-2 py-1 bg-gray-700 text-gray-300 rounded">
                        {iface.name} ({iface.type})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(stats.interfaces)
                .filter(([name, interfaceStats]) => 
                  name && 
                  interfaceStats && 
                  typeof interfaceStats === 'object' &&
                  typeof interfaceStats.packets === 'number' &&
                  typeof interfaceStats.threats === 'number'
                )
                .map(([name, interfaceStats]) => (
              <div key={name} className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    {getInterfaceIcon(interfaceStats.type)}
                    <span className="text-white font-medium">{name}</span>
                    <span className="text-xs px-2 py-1 bg-blue-900/50 text-blue-300 rounded">
                      {interfaceStats.type.toUpperCase()}
                    </span>
                  </div>
                  <div className={`w-3 h-3 rounded-full ${
                    interfaceStats.active ? 'bg-green-400 animate-pulse' : 'bg-red-400'
                  }`} />
                </div>
                
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-blue-400 text-lg font-bold">{(interfaceStats.packets || 0).toLocaleString()}</div>
                    <div className="text-gray-400 text-xs">Packets</div>
                  </div>
                  <div>
                    <div className="text-red-400 text-lg font-bold">{interfaceStats.threats || 0}</div>
                    <div className="text-gray-400 text-xs">Threats</div>
                  </div>
                  <div>
                    <div className="text-green-400 text-lg font-bold">
                      {((interfaceStats.bytes || 0) / 1024 / 1024).toFixed(1)}MB
                    </div>
                    <div className="text-gray-400 text-xs">Data</div>
                  </div>
                  <div>
                    <div className="text-orange-400 text-lg font-bold">
                      {(interfaceStats.threat_rate || 0).toFixed(2)}%
                    </div>
                    <div className="text-gray-400 text-xs">Threat Rate</div>
                  </div>
                </div>

                {/* Protocol Distribution */}
                {interfaceStats.protocol_distribution && Object.keys(interfaceStats.protocol_distribution).length > 0 && (
                  <div className="mt-3 pt-3 border-t border-gray-700">
                    <p className="text-xs text-gray-400 mb-2">Protocol Distribution:</p>
                    <div className="flex space-x-2">
                      {Object.entries(interfaceStats.protocol_distribution)
                        .filter(([protocol, count]) => protocol && typeof count === 'number')
                        .map(([protocol, count]) => (
                        <span key={protocol} className="text-xs px-2 py-1 bg-gray-800 text-gray-300 rounded">
                          {protocol}: {count}
                        </span>
                        ))}
                    </div>
                  </div>
                )}
              </div>
                ))}
            </div>
          )}
        </div>
      )}

      {/* Recent Threats */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <Shield className="h-5 w-5 text-red-400 mr-2" />
          Recent Interface Threats
        </h3>
        
        {!recentThreats || recentThreats.length === 0 ? (
          <div className="text-center py-8">
            <Shield className="h-12 w-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-400">No threats detected on monitored interfaces</p>
            {!isMonitoring && isConnected && (
              <p className="text-gray-500 text-sm mt-2">Click "Start Monitoring" to begin threat detection</p>
            )}
          </div>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {recentThreats
              .filter(threat => 
                threat && 
                threat.id && 
                threat.timestamp && 
                threat.source_ip &&
                threat.destination_ip &&
                typeof threat.severity === 'number' &&
                typeof threat.confidence === 'number'
              )
              .map((threat) => (
              <div key={threat.id} className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    {getInterfaceIcon(threat.interface_type || 'ethernet')}
                    <div>
                      <div className="text-white text-sm font-medium">
                        {threat.source_ip || 'Unknown'} → {threat.destination_ip || 'Unknown'}
                      </div>
                      <div className="text-gray-400 text-xs">
                        {threat.interface || 'Unknown'} ({threat.interface_type || 'unknown'}) • {threat.protocol || 'Unknown'}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-sm font-medium ${getSeverityColor(threat.severity || 1)}`}>
                      Severity: {threat.severity || 1}
                    </div>
                    <div className="text-gray-400 text-xs">
                      {threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'Unknown time'}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getThreatTypeColor(threat.threat_type || 'unknown')}`}>
                      {(threat.threat_type || 'unknown').replace('_', ' ').toUpperCase()}
                    </span>
                    <span className="text-xs text-gray-400">
                      Confidence: {((threat.confidence || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                </div>
                
                <p className="text-gray-300 text-sm mt-2">{threat.description || 'No description available'}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Monitoring Log */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Monitoring Log</h3>
          <button
            onClick={() => setMonitoringLog([])}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            Clear Log
          </button>
        </div>
        
        <div className="bg-gray-900 rounded-lg p-4 h-48 overflow-y-auto font-mono text-sm">
          {monitoringLog.length === 0 ? (
            <p className="text-gray-500">No log entries yet...</p>
          ) : (
            monitoringLog.map((entry, index) => (
              <div key={index} className="text-gray-300 mb-1">
                {entry}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Setup Instructions */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">Setup Instructions</h3>
        <div className="space-y-4">
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-medium mb-2">1. Install Dependencies</h4>
            <code className="text-green-400 text-sm">pip install scapy psutil</code>
            <p className="text-gray-400 text-xs mt-1">Required for packet capture and interface monitoring</p>
          </div>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-medium mb-2">2. Run with Privileges</h4>
            <div className="space-y-1 text-sm">
              <div className="text-gray-300"><strong className="text-white">Linux/macOS:</strong> <code className="text-green-400 bg-gray-800 px-1 rounded">sudo python real_time_interface_monitor.py</code></div>
              <div className="text-gray-300"><strong className="text-white">Windows:</strong> Run Command Prompt as Administrator</div>
            </div>
            <p className="text-gray-400 text-xs mt-1">Required for raw packet capture</p>
          </div>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-medium mb-2">3. Start API Server</h4>
            <code className="text-green-400 text-sm bg-gray-800 px-1 rounded">python real_time_monitor_api.py</code>
            <p className="text-gray-400 text-xs mt-1">Provides REST API for dashboard integration</p>
          </div>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-medium mb-2">4. ML Model Features</h4>
            <ul className="list-disc list-inside text-gray-400 text-xs">
              <li>Persistent learning - model remembers what it learns</li>
              <li>Real-time threat classification</li>
              <li>Automatic retraining with new data</li>
              <li>25+ advanced features for threat detection</li>
              <li>Wi-Fi and Ethernet interface monitoring</li>
              <li>Behavioral anomaly detection</li>
            </ul>
          </div>
        </div>
        
        {/* Available Interfaces Display */}
        {availableInterfaces.length > 0 && (
          <div className="mt-6 bg-blue-900/20 border border-blue-700/50 rounded-lg p-4">
            <h4 className="text-blue-300 font-medium mb-2">Detected Network Interfaces</h4>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {availableInterfaces.map(iface => (
                <div key={iface.name} className="flex items-center space-x-2 text-sm">
                  {getInterfaceIcon(iface.type)}
                  <span className="text-white">{iface.name}</span>
                  <span className="text-xs px-1 py-0.5 bg-blue-800 text-blue-200 rounded">
                    {iface.type}
                  </span>
                  <div className={`w-2 h-2 rounded-full ${iface.is_up ? 'bg-green-400' : 'bg-red-400'}`} />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}