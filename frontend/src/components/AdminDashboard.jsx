import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { 
  Play, 
  Pause, 
  Stop, 
  RefreshCw, 
  AlertCircle, 
  CheckCircle, 
  Clock,
  Activity,
  Server
} from 'lucide-react';

const AdminDashboard = () => {
  const [scans, setScans] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [socket, setSocket] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);

  useEffect(() => {
    // Initialize Socket.IO connection
    const newSocket = io('http://localhost:5001');
    setSocket(newSocket);

    newSocket.on('connect', () => {
      console.log('Connected to real-time monitoring');
    });

    newSocket.on('scan_paused', (data) => {
      updateScanStatus(data.scan_id, 'paused');
    });

    newSocket.on('scan_resumed', (data) => {
      updateScanStatus(data.scan_id, 'processing');
    });

    newSocket.on('scan_stopped', (data) => {
      updateScanStatus(data.scan_id, 'stopped');
    });

    return () => newSocket.close();
  }, []);

  useEffect(() => {
    fetchScans();
    fetchWorkers();
    const interval = setInterval(fetchScans, 3000); // Refresh every 3 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5001/api/admin/scans', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setScans(data.scans);
      }
    } catch (error) {
      console.error('Error fetching scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchWorkers = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5001/api/admin/workers', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setWorkers(data.workers);
      }
    } catch (error) {
      console.error('Error fetching workers:', error);
    }
  };

  const fetchScanLogs = async (scanId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:5001/api/admin/scans/${scanId}/logs`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setScanLogs(data.logs);
      }
    } catch (error) {
      console.error('Error fetching scan logs:', error);
    }
  };

  const updateScanStatus = (scanId, status) => {
    setScans(prevScans => 
      prevScans.map(scan => 
        scan.id === scanId ? { ...scan, status } : scan
      )
    );
  };

  const handleScanAction = async (scanId, action) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`http://localhost:5001/api/admin/scans/${scanId}/${action}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        fetchScans(); // Refresh the list
      }
    } catch (error) {
      console.error(`Error ${action} scan:`, error);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'processing':
        return <Activity className="w-4 h-4 text-blue-500 animate-pulse" />;
      case 'pending':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <AlertCircle className="w-4 h-4 text-red-500" />;
      case 'paused':
        return <Pause className="w-4 h-4 text-orange-500" />;
      case 'stopped':
        return <Stop className="w-4 h-4 text-gray-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'processing': return 'bg-blue-100 text-blue-800';
      case 'pending': return 'bg-yellow-100 text-yellow-800';
      case 'completed': return 'bg-green-100 text-green-800';
      case 'failed': return 'bg-red-100 text-red-800';
      case 'paused': return 'bg-orange-100 text-orange-800';
      case 'stopped': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const activeScans = scans.filter(scan => ['processing', 'pending', 'paused'].includes(scan.status));
  const completedScans = scans.filter(scan => scan.status === 'completed');
  const failedScans = scans.filter(scan => scan.status === 'failed');

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Admin Dashboard</h1>
          <p className="text-gray-600">Real-time scan monitoring and control</p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Activity className="w-6 h-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Scans</p>
                <p className="text-2xl font-bold text-gray-900">{activeScans.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <div className="p-2 bg-green-100 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Completed</p>
                <p className="text-2xl font-bold text-gray-900">{completedScans.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <div className="p-2 bg-red-100 rounded-lg">
                <AlertCircle className="w-6 h-6 text-red-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Failed</p>
                <p className="text-2xl font-bold text-gray-900">{failedScans.length}</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-center">
              <div className="p-2 bg-purple-100 rounded-lg">
                <Server className="w-6 h-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Workers</p>
                <p className="text-2xl font-bold text-gray-900">{workers.length}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Workers Status */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Worker Status</h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {workers.map(worker => (
                <div key={worker.id} className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium">{worker.id}</span>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      worker.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {worker.status}
                    </span>
                  </div>
                  <div className="text-sm text-gray-600">
                    <p>Completed: {worker.completed_scans}</p>
                    <p>Uptime: {worker.uptime}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Scans Table */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Scan Management</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Progress
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    User
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {scans.map(scan => (
                  <tr key={scan.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {scan.target}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.scan_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(scan.status)}
                        <span className={`ml-2 text-sm font-medium ${getStatusColor(scan.status)} px-2 py-1 rounded-full`}>
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div 
                          className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                          style={{ width: `${scan.progress}%` }}
                        ></div>
                      </div>
                      <span className="text-xs text-gray-500">{scan.progress}%</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.user}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {scan.status === 'processing' && (
                          <>
                            <button
                              onClick={() => handleScanAction(scan.id, 'pause')}
                              className="text-orange-600 hover:text-orange-900"
                              title="Pause scan"
                            >
                              <Pause className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleScanAction(scan.id, 'stop')}
                              className="text-red-600 hover:text-red-900"
                              title="Stop scan"
                            >
                              <Stop className="w-4 h-4" />
                            </button>
                          </>
                        )}
                        {scan.status === 'paused' && (
                          <button
                            onClick={() => handleScanAction(scan.id, 'resume')}
                            className="text-green-600 hover:text-green-900"
                            title="Resume scan"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => {
                            setSelectedScan(scan);
                            fetchScanLogs(scan.id);
                          }}
                          className="text-blue-600 hover:text-blue-900"
                          title="View details"
                        >
                          <Activity className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Scan Details Modal */}
        {selectedScan && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-2xl w-full max-h-96 overflow-y-auto">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold">Scan Details: {selectedScan.target}</h3>
                <button
                  onClick={() => setSelectedScan(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ×
                </button>
              </div>
              <div className="space-y-4">
                <div>
                  <strong>Target:</strong> {selectedScan.target}
                </div>
                <div>
                  <strong>Type:</strong> {selectedScan.scan_type}
                </div>
                <div>
                  <strong>Status:</strong> {selectedScan.status}
                </div>
                <div>
                  <strong>Progress:</strong> {selectedScan.progress}%
                </div>
                <div>
                  <strong>Started:</strong> {selectedScan.start_time}
                </div>
                <div>
                  <strong>Vulnerabilities:</strong> {selectedScan.vulnerability_count}
                </div>
                <div>
                  <strong>Configuration:</strong>
                  <pre className="text-xs bg-gray-100 p-2 rounded mt-1">
                    {JSON.stringify(selectedScan.config, null, 2)}
                  </pre>
                </div>
                {scanLogs.length > 0 && (
                  <div>
                    <strong>Logs:</strong>
                    <div className="text-xs bg-gray-100 p-2 rounded mt-1 max-h-32 overflow-y-auto">
                      {scanLogs.map((log, index) => (
                        <div key={index} className="mb-1">
                          [{log.timestamp}] {log.level}: {log.message}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminDashboard;