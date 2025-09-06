import React, { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { FiTrendingUp, FiTrendingDown, FiActivity, FiAlertTriangle, FiClock, FiTarget, FiWifi, FiWifiOff, FiSettings, FiZap } from 'react-icons/fi';
import forecastingApi from '../services/forecastingApi';

const ForecastingDashboard = () => {
  const [forecastData, setForecastData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedModel, setSelectedModel] = useState('auto');
  const [availableModels, setAvailableModels] = useState(['auto', 'enhanced_moving_average']);
  const [periods, setPeriods] = useState(14);

  // Fetch forecasting data from API
  useEffect(() => {
    const fetchForecastData = async () => {
      try {
        setLoading(true);
        const result = await forecastingApi.getFullForecast(periods, selectedModel);
        
        if (result.success) {
          setForecastData(result.data);
          setAvailableModels(result.data.available_models || ['auto', 'enhanced_moving_average']);
          setError(null);
        } else {
          throw new Error(result.error || 'Failed to fetch forecast data');
        }
      } catch (err) {
        console.error('Error fetching forecast data:', err);
        setError(err.message);
        // Fallback to mock data for development
        const mockData = forecastingApi.generateMockData();
        mockData.available_models = availableModels;
        mockData.model_type = selectedModel;
        setForecastData(mockData);
      } finally {
        setLoading(false);
      }
    };

    fetchForecastData();
    // Refresh every 5 minutes
    const interval = setInterval(fetchForecastData, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [selectedModel, periods, availableModels]);



  // Prepare chart data for forecasting visualization
  const prepareChartData = (metric, label, color) => {
    if (!forecastData?.metrics?.[metric]) return null;

    const data = forecastData.metrics[metric];
    const labels = data.map(item => {
      const date = new Date(item.date);
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });

    const values = data.map(item => item.predicted_value);
    const upperBound = data.map(item => item.upper_bound);
    const lowerBound = data.map(item => Math.max(0, item.lower_bound));

    return {
      labels,
      datasets: [
        {
          label: label,
          data: values,
          borderColor: color,
          backgroundColor: `${color}20`,
          tension: 0.4,
          fill: false,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
        {
          label: 'Confidence Band (Upper)',
          data: upperBound,
          borderColor: `${color}40`,
          backgroundColor: `${color}10`,
          tension: 0.4,
          fill: '+1',
          pointRadius: 0,
          borderDash: [5, 5],
        },
        {
          label: 'Confidence Band (Lower)',
          data: lowerBound,
          borderColor: `${color}40`,
          backgroundColor: `${color}10`,
          tension: 0.4,
          fill: false,
          pointRadius: 0,
          borderDash: [5, 5],
        }
      ]
    };
  };

  // Calculate trend direction using API service
  const getTrend = (metric) => {
    const trend = forecastingApi.calculateTrend(forecastData, metric);
    if (!trend) return null;
    
    return {
      direction: trend.direction === 'increasing' ? 'up' : 'down',
      percentage: Math.abs(trend.percentageChange).toFixed(1),
      isSignificant: trend.isSignificant
    };
  };

  // Get current forecast value
  const getCurrentForecast = (metric) => {
    if (!forecastData?.metrics?.[metric]) return null;
    const data = forecastData.metrics[metric];
    return data.length > 0 ? data[0].predicted_value.toFixed(1) : null;
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      mode: 'index',
      intersect: false,
    },
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
          color: document.documentElement.classList.contains('dark') ? 'white' : 'black',
          filter: (legendItem) => !legendItem.text.includes('Confidence Band')
        }
      },
      tooltip: {
        callbacks: {
          afterLabel: (context) => {
            if (context.datasetIndex === 0) {
              const confidence = forecastData?.metrics?.[Object.keys(forecastData.metrics)[Math.floor(context.datasetIndex / 3)]]?.[context.dataIndex]?.confidence;
              return confidence ? `Confidence: ${(confidence * 100).toFixed(0)}%` : '';
            }
            return '';
          }
        }
      }
    }
  };

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-4"></div>
          <div className="h-64 bg-gray-200 dark:bg-gray-700 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Controls Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="block text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
              Forecasting Model
            </label>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {availableModels.map(model => (
                <option key={model} value={model}>
                  {model === 'auto' ? 'Auto (Best Available)' : 
                   model === 'prophet' ? 'Prophet (Advanced)' :
                   model === 'lstm' ? 'LSTM (Deep Learning)' :
                   'Enhanced Moving Average'}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
              Forecast Periods
            </label>
            <select
              value={periods}
              onChange={(e) => setPeriods(Number(e.target.value))}
              className="bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={7}>7 days</option>
              <option value={14}>14 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
          </div>
          <div className="text-sm text-gray-500 dark:text-gray-400">
            <div className="flex items-center gap-2">
              <FiSettings className="w-4 h-4" />
              <span>Model: {forecastData?.model_type || selectedModel}</span>
            </div>
            {forecastData?.model_performance && (
              <div className="flex items-center gap-2 mt-1">
                <FiZap className="w-4 h-4" />
                <span>Accuracy: {(forecastData.model_performance.accuracy * 100).toFixed(1)}%</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Forecast Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Vulnerability Count Forecast */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-orange-100 dark:bg-orange-900 text-orange-600 dark:text-orange-300">
                <FiTarget className="w-6 h-6" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Predicted Vulnerabilities</p>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {getCurrentForecast('vulnerability_count') || '--'}
                </p>
                {forecastData?.metrics?.vulnerability_count?.[0]?.confidence && (
                  <div className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                    Confidence: {(forecastData.metrics.vulnerability_count[0].confidence * 100).toFixed(0)}%
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {getTrend('vulnerability_count') && (
                <>
                  {getTrend('vulnerability_count').direction === 'up' ? (
                    <FiTrendingUp className="w-5 h-5 text-red-500" />
                  ) : (
                    <FiTrendingDown className="w-5 h-5 text-green-500" />
                  )}
                  <span className={`ml-1 text-sm font-medium ${
                    getTrend('vulnerability_count').direction === 'up' ? 'text-red-500' : 'text-green-500'
                  }`}>
                    {getTrend('vulnerability_count').percentage}%
                  </span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Risk Score Forecast */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-red-100 dark:bg-red-900 text-red-600 dark:text-red-300">
                <FiAlertTriangle className="w-6 h-6" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Predicted Risk Score</p>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {getCurrentForecast('risk_score') || '--'}
                </p>
                {forecastData?.metrics?.risk_score?.[0]?.confidence && (
                  <div className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                    Confidence: {(forecastData.metrics.risk_score[0].confidence * 100).toFixed(0)}%
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {getTrend('risk_score') && (
                <>
                  {getTrend('risk_score').direction === 'up' ? (
                    <FiTrendingUp className="w-5 h-5 text-red-500" />
                  ) : (
                    <FiTrendingDown className="w-5 h-5 text-green-500" />
                  )}
                  <span className={`ml-1 text-sm font-medium ${
                    getTrend('risk_score').direction === 'up' ? 'text-red-500' : 'text-green-500'
                  }`}>
                    {getTrend('risk_score').percentage}%
                  </span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Remediation Time Forecast */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300">
                <FiClock className="w-6 h-6" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Avg Remediation Time</p>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {getCurrentForecast('remediation_time') ? `${getCurrentForecast('remediation_time')}d` : '--'}
                </p>
                {forecastData?.metrics?.remediation_time?.[0]?.confidence && (
                  <div className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                    Confidence: {(forecastData.metrics.remediation_time[0].confidence * 100).toFixed(0)}%
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center">
              {getTrend('remediation_time') && (
                <>
                  {getTrend('remediation_time').direction === 'up' ? (
                    <FiTrendingUp className="w-5 h-5 text-red-500" />
                  ) : (
                    <FiTrendingDown className="w-5 h-5 text-green-500" />
                  )}
                  <span className={`ml-1 text-sm font-medium ${
                    getTrend('remediation_time').direction === 'up' ? 'text-red-500' : 'text-green-500'
                  }`}>
                    {getTrend('remediation_time').percentage}%
                  </span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Forecast Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Count Forecast Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Vulnerability Count Forecast</h3>
            <span className="text-sm text-gray-500 dark:text-gray-400">14-day prediction</span>
          </div>
          <div className="h-64">
            {prepareChartData('vulnerability_count', 'Vulnerabilities', '#F97316') && (
              <Line 
                data={prepareChartData('vulnerability_count', 'Vulnerabilities', '#F97316')} 
                options={chartOptions}
              />
            )}
          </div>
        </div>

        {/* Risk Score Forecast Chart */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Risk Score Forecast</h3>
            <span className="text-sm text-gray-500 dark:text-gray-400">14-day prediction</span>
          </div>
          <div className="h-64">
            {prepareChartData('risk_score', 'Risk Score', '#DC2626') && (
              <Line 
                data={prepareChartData('risk_score', 'Risk Score', '#DC2626')} 
                options={chartOptions}
              />
            )}
          </div>
        </div>
      </div>

      {/* Recommendations */}
      {forecastData?.recommendations && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">AI Recommendations</h3>
          <div className="space-y-3">
            {forecastData.recommendations.map((recommendation, index) => (
              <div key={index} className="flex items-start">
                <div className="flex-shrink-0">
                  <FiActivity className="w-5 h-5 text-blue-500 mt-0.5" />
                </div>
                <p className="ml-3 text-sm text-gray-600 dark:text-gray-300">{recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* API Status Indicator */}
      <div className="flex items-center justify-center space-x-4">
        <div className="flex items-center">
          {error ? (
            <>
              <FiWifiOff className="w-4 h-4 text-red-500" />
              <span className="ml-2 text-sm text-red-600 dark:text-red-400">Offline Mode</span>
            </>
          ) : (
            <>
              <FiWifi className="w-4 h-4 text-green-500" />
              <span className="ml-2 text-sm text-green-600 dark:text-green-400">Live Data</span>
            </>
          )}
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
          <div className="flex">
            <FiAlertTriangle className="w-5 h-5 text-yellow-400" />
            <div className="ml-3">
              <p className="text-sm text-yellow-700 dark:text-yellow-200">
                Unable to fetch live forecast data. Showing sample predictions.
              </p>
              <p className="text-xs text-yellow-600 dark:text-yellow-300 mt-1">
                Error: {error}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Metadata */}
      {forecastData?.timestamp && (
        <div className="text-center">
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Last updated: {new Date(forecastData.timestamp).toLocaleString()}
          </p>
        </div>
      )}
    </div>
  );
};

export default ForecastingDashboard;