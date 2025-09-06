import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { FiDownload, FiAlertTriangle, FiInfo, FiArrowLeft, FiClock, FiCheckCircle } from 'react-icons/fi';

// Mock data - in a real app, this would come from API
const mockScanData = {
  id: 'scan-1',
  target: 'example.com',
  type: 'web',
  status: 'completed',
  startTime: '2023-04-15T10:30:00Z',
  endTime: '2023-04-15T10:45:23Z',
  description: 'Routine security check of the main website',
  scanOptions: {
    portScan: true,
    vulnDetection: true,
    sslCheck: true,
    headerAnalysis: true,
    dirBruteforce: false,
    deepScan: false
  },
  vulnerabilities: [
    {
      id: 'vuln-1',
      title: 'Cross-Site Scripting (XSS)',
      severity: 'high',
      description: 'Reflected XSS vulnerability found in search parameter',
      location: '/search?q=',
      remediation: 'Implement proper input validation and output encoding',
      cvss: 7.5,
      references: ['https://owasp.org/www-community/attacks/xss/']
    },
    {
      id: 'vuln-2',
      title: 'Outdated SSL/TLS Version',
      severity: 'medium',
      description: 'Server supports TLS 1.0 which is deprecated',
      location: 'example.com:443',
      remediation: 'Disable TLS 1.0/1.1 and only enable TLS 1.2 and above',
      cvss: 5.3,
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-3389']
    },
    {
      id: 'vuln-3',
      title: 'Missing HTTP Security Headers',
      severity: 'low',
      description: 'The application is missing security headers such as Content-Security-Policy',
      location: 'HTTP Response Headers',
      remediation: 'Implement recommended security headers',
      cvss: 3.1,
      references: ['https://owasp.org/www-project-secure-headers/']
    }
  ]
};

const ScanDetails = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // In a real app, this would fetch data from the API
    const fetchScanDetails = async () => {
      try {
        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 800));
        setScan(mockScanData);
      } catch (err) {
        setError('Failed to load scan details');
        console.error('Error fetching scan details:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchScanDetails();
  }, [scanId]);

  // Format date
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  // Calculate duration
  const calculateDuration = (start, end) => {
    const startTime = new Date(start);
    const endTime = new Date(end);
    const durationMs = endTime - startTime;
    const minutes = Math.floor(durationMs / 60000);
    const seconds = Math.floor((durationMs % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  // Get severity badge color
  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300';
      case 'low':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/30 border-l-4 border-red-500 p-4 rounded">
        <div className="flex items-center">
          <FiAlertTriangle className="text-red-500 mr-2" />
          <p className="text-red-800 dark:text-red-300">{error}</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/30 border-l-4 border-yellow-500 p-4 rounded">
        <div className="flex items-center">
          <FiInfo className="text-yellow-500 mr-2" />
          <p className="text-yellow-800 dark:text-yellow-300">Scan not found</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with back button */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
        <div className="flex items-center">
          <Link to="/dashboard" className="mr-4 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
            <FiArrowLeft className="w-5 h-5" />
          </Link>
          <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Scan Results: {scan.target}</h1>
        </div>
        <div className="mt-4 md:mt-0 flex space-x-3">
          <button className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            <FiDownload className="mr-2 -ml-1 h-5 w-5" />
            Export PDF
          </button>
        </div>
      </div>

      {/* Scan Overview */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
        <div className="p-6 border-b dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Scan Overview</h2>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Target</h3>
              <p className="mt-1 text-sm text-gray-900 dark:text-white">{scan.target}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Scan Type</h3>
              <p className="mt-1 text-sm text-gray-900 dark:text-white capitalize">{scan.type}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Status</h3>
              <p className="mt-1 text-sm">
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  scan.status === 'completed' 
                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' 
                    : scan.status === 'running'
                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                }`}>
                  {scan.status === 'completed' ? <FiCheckCircle className="mr-1" /> : 
                   scan.status === 'running' ? <FiClock className="mr-1" /> : null}
                  {scan.status}
                </span>
              </p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Start Time</h3>
              <p className="mt-1 text-sm text-gray-900 dark:text-white">{formatDate(scan.startTime)}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">End Time</h3>
              <p className="mt-1 text-sm text-gray-900 dark:text-white">
                {scan.endTime ? formatDate(scan.endTime) : 'In Progress'}
              </p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Duration</h3>
              <p className="mt-1 text-sm text-gray-900 dark:text-white">
                {scan.endTime ? calculateDuration(scan.startTime, scan.endTime) : 'Running...'}
              </p>
            </div>
            {scan.description && (
              <div className="md:col-span-2 lg:col-span-3">
                <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">Description</h3>
                <p className="mt-1 text-sm text-gray-900 dark:text-white">{scan.description}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
        <div className="p-6 border-b dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Vulnerabilities Found</h2>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {scan.vulnerabilities.length > 0 ? (
            scan.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="p-6">
                <div className="flex flex-col md:flex-row md:items-start md:justify-between">
                  <div className="flex-1">
                    <div className="flex items-center">
                      <h3 className="text-lg font-medium text-gray-900 dark:text-white">{vuln.title}</h3>
                      <span className={`ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                      <span className="font-medium">CVSS Score:</span> {vuln.cvss}
                    </p>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                      <span className="font-medium">Location:</span> {vuln.location}
                    </p>
                    <div className="mt-3">
                      <p className="text-sm text-gray-900 dark:text-white">{vuln.description}</p>
                    </div>
                    <div className="mt-4">
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">Remediation</h4>
                      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">{vuln.remediation}</p>
                    </div>
                    {vuln.references && vuln.references.length > 0 && (
                      <div className="mt-4">
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">References</h4>
                        <ul className="mt-1 list-disc list-inside text-sm text-blue-600 dark:text-blue-400">
                          {vuln.references.map((ref, index) => (
                            <li key={index}>
                              <a href={ref} target="_blank" rel="noopener noreferrer" className="hover:underline">
                                {ref}
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="p-6 text-center">
              <p className="text-gray-500 dark:text-gray-400">No vulnerabilities found</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanDetails;