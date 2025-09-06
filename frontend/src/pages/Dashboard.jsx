import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FiAlertTriangle, FiShield, FiActivity, FiClock, FiPlus, FiTrendingUp } from 'react-icons/fi';
import { Doughnut, Line } from 'react-chartjs-2';
import { Chart, ArcElement, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';
import ForecastingDashboard from '../components/ForecastingDashboard';

// Register Chart.js components
Chart.register(ArcElement, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

// Mock data - in a real app, this would come from API
const mockStats = {
  totalScans: 24,
  activeScans: 2,
  completedScans: 22,
  vulnerabilities: {
    critical: 5,
    high: 12,
    medium: 28,
    low: 43,
    info: 17
  },
  recentScans: [
    { id: 'scan-1', target: 'example.com', type: 'web', status: 'completed', timestamp: '2023-04-15T10:30:00Z', vulnerabilities: 8 },
    { id: 'scan-2', target: '192.168.1.1', type: 'network', status: 'completed', timestamp: '2023-04-14T14:45:00Z', vulnerabilities: 3 },
    { id: 'scan-3', target: 'api.example.org', type: 'web', status: 'running', timestamp: '2023-04-16T09:15:00Z', vulnerabilities: 0 },
  ],
  scanHistory: [
    { date: 'Apr 10', scans: 2, vulnerabilities: 7 },
    { date: 'Apr 11', scans: 1, vulnerabilities: 3 },
    { date: 'Apr 12', scans: 3, vulnerabilities: 12 },
    { date: 'Apr 13', scans: 2, vulnerabilities: 5 },
    { date: 'Apr 14', scans: 4, vulnerabilities: 9 },
    { date: 'Apr 15', scans: 3, vulnerabilities: 8 },
    { date: 'Apr 16', scans: 2, vulnerabilities: 6 },
  ]
};

const Dashboard = () => {
  const [stats, setStats] = useState(mockStats);

  // In a real app, this would fetch data from the API
  useEffect(() => {
    // Simulating API call
    setStats(mockStats);
  }, []);

  // Prepare chart data
  const vulnerabilityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [
      {
        data: [
          stats.vulnerabilities.critical,
          stats.vulnerabilities.high,
          stats.vulnerabilities.medium,
          stats.vulnerabilities.low,
          stats.vulnerabilities.info
        ],
        backgroundColor: [
          '#DC2626', // red-600
          '#F97316', // orange-500
          '#FBBF24', // amber-400
          '#34D399', // emerald-400
          '#60A5FA', // blue-400
        ],
        borderWidth: 1,
      },
    ],
  };

  const scanHistoryChartData = {
    labels: stats.scanHistory.map(item => item.date),
    datasets: [
      {
        label: 'Scans',
        data: stats.scanHistory.map(item => item.scans),
        borderColor: '#3B82F6', // blue-500
        backgroundColor: 'rgba(59, 130, 246, 0.5)',
        tension: 0.3,
      },
      {
        label: 'Vulnerabilities',
        data: stats.scanHistory.map(item => item.vulnerabilities),
        borderColor: '#F97316', // orange-500
        backgroundColor: 'rgba(249, 115, 22, 0.5)',
        tension: 0.3,
      },
    ],
  };

  // Format date
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Dashboard</h1>
        <Link
          to="/scans/new"
          className="mt-4 md:mt-0 inline-flex items-center px-4 py-2 bg-blue-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-blue-700 active:bg-blue-800 focus:outline-none focus:border-blue-800 focus:ring ring-blue-300 disabled:opacity-25 transition"
        >
          <FiPlus className="mr-2" />
          New Scan
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300">
              <FiActivity className="w-6 h-6" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Total Scans</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{stats.totalScans}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-green-100 dark:bg-green-900 text-green-600 dark:text-green-300">
              <FiClock className="w-6 h-6" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Active Scans</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{stats.activeScans}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-purple-100 dark:bg-purple-900 text-purple-600 dark:text-purple-300">
              <FiShield className="w-6 h-6" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Completed Scans</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{stats.completedScans}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-red-100 dark:bg-red-900 text-red-600 dark:text-red-300">
              <FiAlertTriangle className="w-6 h-6" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Critical Vulnerabilities</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">{stats.vulnerabilities.critical}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Predictive Analytics Section */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300">
              <FiTrendingUp className="w-6 h-6" />
            </div>
            <div className="ml-4">
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Predictive Security Analytics</h2>
              <p className="text-sm text-gray-600 dark:text-gray-300">AI-powered 14-day security forecasts with confidence intervals</p>
            </div>
          </div>
        </div>
        <ForecastingDashboard />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Vulnerability Breakdown</h2>
          <div className="h-64 flex items-center justify-center">
            <Doughnut 
              data={vulnerabilityChartData} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'right',
                    labels: {
                      color: document.documentElement.classList.contains('dark') ? 'white' : 'black'
                    }
                  }
                }
              }} 
            />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan History</h2>
          <div className="h-64">
            <Line 
              data={scanHistoryChartData} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: {
                    beginAtZero: true,
                    ticks: {
                      color: document.documentElement.classList.contains('dark') ? 'white' : 'black'
                    },
                    grid: {
                      color: document.documentElement.classList.contains('dark') ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                    }
                  },
                  x: {
                    ticks: {
                      color: document.documentElement.classList.contains('dark') ? 'white' : 'black'
                    },
                    grid: {
                      color: document.documentElement.classList.contains('dark') ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                    }
                  }
                },
                plugins: {
                  legend: {
                    labels: {
                      color: document.documentElement.classList.contains('dark') ? 'white' : 'black'
                    }
                  }
                }
              }} 
            />
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="p-6 border-b dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Scans</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Target</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Date</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Vulnerabilities</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {stats.recentScans.map((scan) => (
                <tr key={scan.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link to={`/scans/${scan.id}`} className="text-blue-600 dark:text-blue-400 hover:underline">
                      {scan.target}
                    </Link>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="capitalize">{scan.type}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      scan.status === 'completed' 
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' 
                        : scan.status === 'running'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                        : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(scan.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {scan.vulnerabilities}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="p-4 border-t dark:border-gray-700">
          <Link to="/scans" className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline">
            View all scans
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;