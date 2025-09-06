/**
 * Forecasting API Service
 * Handles communication with the backend forecasting endpoints
 */

const API_BASE_URL = 'http://localhost:5002/api';

class ForecastingApiService {
  constructor() {
    this.baseURL = API_BASE_URL;
  }

  /**
   * Fetch complete forecast data for all metrics
   * @returns {Promise<Object>} Complete forecast data
   */
  async getFullForecast() {
    try {
      const response = await fetch(`${this.baseURL}/forecast`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error fetching full forecast:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Fetch forecast data for a specific metric
   * @param {string} metric - The metric to forecast (vulnerability_count, risk_score, remediation_time)
   * @returns {Promise<Object>} Specific metric forecast data
   */
  async getMetricForecast(metric) {
    try {
      const response = await fetch(`${this.baseURL}/forecast/${metric}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error(`Error fetching ${metric} forecast:`, error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Check API health status
   * @returns {Promise<Object>} Health status
   */
  async checkHealth() {
    try {
      const response = await fetch(`${this.baseURL.replace('/api', '')}/health`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      return {
        success: true,
        healthy: data.status === 'healthy',
        service: data.service || 'forecast-api'
      };
    } catch (error) {
      console.error('Error checking API health:', error);
      return {
        success: false,
        healthy: false,
        error: error.message
      };
    }
  }

  /**
   * Get available forecast metrics
   * @returns {Array<string>} List of available metrics
   */
  getAvailableMetrics() {
    return ['vulnerability_count', 'risk_score', 'remediation_time'];
  }

  /**
   * Format forecast data for chart visualization
   * @param {Object} forecastData - Raw forecast data from API
   * @param {string} metric - Specific metric to format
   * @returns {Object} Formatted chart data
   */
  formatChartData(forecastData, metric) {
    if (!forecastData?.metrics?.[metric]) {
      return null;
    }

    const data = forecastData.metrics[metric];
    const labels = data.map(item => {
      const date = new Date(item.date);
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    });

    const values = data.map(item => item.predicted_value);
    const confidenceIntervals = data.map(item => ({
      upper: item.predicted_value + (item.predicted_value * (1 - item.confidence) * 0.5),
      lower: Math.max(0, item.predicted_value - (item.predicted_value * (1 - item.confidence) * 0.5))
    }));

    return {
      labels,
      values,
      confidenceIntervals,
      metadata: {
        periods: data.length,
        avgConfidence: data.reduce((sum, item) => sum + item.confidence, 0) / data.length,
        modelType: data[0]?.model_type || 'unknown'
      }
    };
  }

  /**
   * Calculate trend analysis for a metric
   * @param {Object} forecastData - Raw forecast data from API
   * @param {string} metric - Specific metric to analyze
   * @returns {Object} Trend analysis
   */
  calculateTrend(forecastData, metric) {
    if (!forecastData?.metrics?.[metric]) {
      return null;
    }

    const data = forecastData.metrics[metric];
    if (data.length < 2) {
      return null;
    }

    const first = data[0].predicted_value;
    const last = data[data.length - 1].predicted_value;
    const change = last - first;
    const percentageChange = (change / first) * 100;

    return {
      direction: change > 0 ? 'increasing' : change < 0 ? 'decreasing' : 'stable',
      absoluteChange: change,
      percentageChange: percentageChange,
      isSignificant: Math.abs(percentageChange) > 5, // Consider >5% change as significant
      trend: percentageChange > 10 ? 'strong_increase' : 
             percentageChange > 5 ? 'moderate_increase' :
             percentageChange < -10 ? 'strong_decrease' :
             percentageChange < -5 ? 'moderate_decrease' : 'stable'
    };
  }

  /**
   * Generate mock forecast data for development/fallback
   * @returns {Object} Mock forecast data
   */
  generateMockData() {
    const generateMetricData = (baseValue, variance) => {
      return Array.from({ length: 14 }, (_, i) => ({
        date: new Date(Date.now() + i * 24 * 60 * 60 * 1000).toISOString(),
        predicted_value: baseValue + (Math.random() - 0.5) * variance,
        confidence: 0.7 + Math.random() * 0.2,
        model_type: 'moving_average'
      }));
    };

    return {
      forecast_periods: 14,
      metrics: {
        vulnerability_count: generateMetricData(55, 15),
        risk_score: generateMetricData(42, 12),
        remediation_time: generateMetricData(9, 3)
      },
      recommendations: [
        'Moderate vulnerability load - maintain current security processes',
        'Consider increasing scan frequency for critical assets',
        'Review remediation workflows for efficiency improvements',
        'Monitor trending vulnerabilities for proactive patching'
      ],
      timestamp: new Date().toISOString()
    };
  }
}

// Export singleton instance
export default new ForecastingApiService();

// Export class for testing
export { ForecastingApiService };