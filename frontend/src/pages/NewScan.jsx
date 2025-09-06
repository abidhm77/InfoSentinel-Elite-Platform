import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiAlertCircle, FiCheck } from 'react-icons/fi';

const NewScan = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    target: '',
    scanType: 'web',
    scanOptions: {
      portScan: true,
      vulnDetection: true,
      sslCheck: true,
      headerAnalysis: true,
      dirBruteforce: false,
      deepScan: false
    },
    description: ''
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleOptionChange = (e) => {
    const { name, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      scanOptions: {
        ...prev.scanOptions,
        [name]: checked
      }
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      // In a real app, this would be an API call
      console.log('Starting scan with data:', formData);
      
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Redirect to dashboard with success message
      navigate('/dashboard', { 
        state: { 
          notification: {
            type: 'success',
            message: `Scan started for ${formData.target}`
          }
        }
      });
    } catch (err) {
      setError('Failed to start scan. Please try again.');
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white mb-6">New Penetration Test</h1>
        
        {error && (
          <div className="mb-4 bg-red-50 dark:bg-red-900/30 border-l-4 border-red-500 p-4 rounded">
            <div className="flex items-center">
              <FiAlertCircle className="text-red-500 mr-2" />
              <p className="text-red-800 dark:text-red-300">{error}</p>
            </div>
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="space-y-6">
            {/* Target Input */}
            <div>
              <label htmlFor="target" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Target URL or IP Address
              </label>
              <input
                type="text"
                id="target"
                name="target"
                value={formData.target}
                onChange={handleChange}
                placeholder="example.com or 192.168.1.1"
                required
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              />
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Enter a domain, URL, or IP address to scan
              </p>
            </div>
            
            {/* Scan Type Selection */}
            <div>
              <label htmlFor="scanType" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Scan Type
              </label>
              <select
                id="scanType"
                name="scanType"
                value={formData.scanType}
                onChange={handleChange}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              >
                <option value="web">Web Application</option>
                <option value="network">Network</option>
                <option value="system">System</option>
                <option value="comprehensive">Comprehensive (All Types)</option>
              </select>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                Select the type of penetration test to perform
              </p>
            </div>
            
            {/* Scan Options */}
            <div>
              <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Scan Options</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="portScan"
                    name="portScan"
                    checked={formData.scanOptions.portScan}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="portScan" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    Port Scanning
                  </label>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="vulnDetection"
                    name="vulnDetection"
                    checked={formData.scanOptions.vulnDetection}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="vulnDetection" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    Vulnerability Detection
                  </label>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="sslCheck"
                    name="sslCheck"
                    checked={formData.scanOptions.sslCheck}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="sslCheck" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    SSL/TLS Analysis
                  </label>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="headerAnalysis"
                    name="headerAnalysis"
                    checked={formData.scanOptions.headerAnalysis}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="headerAnalysis" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    HTTP Header Analysis
                  </label>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="dirBruteforce"
                    name="dirBruteforce"
                    checked={formData.scanOptions.dirBruteforce}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="dirBruteforce" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    Directory Bruteforce
                  </label>
                </div>
                
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="deepScan"
                    name="deepScan"
                    checked={formData.scanOptions.deepScan}
                    onChange={handleOptionChange}
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <label htmlFor="deepScan" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    Deep Scan (Slower but more thorough)
                  </label>
                </div>
              </div>
            </div>
            
            {/* Description */}
            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description (Optional)
              </label>
              <textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows="3"
                placeholder="Add notes or context about this scan"
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              ></textarea>
            </div>
            
            {/* Submit Button */}
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => navigate('/dashboard')}
                className="mr-4 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
              >
                {loading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Processing...
                  </>
                ) : (
                  <>
                    <FiCheck className="mr-2" />
                    Start Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

export default NewScan;