/**
 * Security Charts Component
 * Creates interactive charts for security statistics with historical data
 * Connects to the security stats history API for real-time data visualization
 */
class SecurityCharts {
  constructor(containerId, options = {}) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      console.error(`Container with ID "${containerId}" not found`);
      return;
    }

    // Default options
    this.options = {
      timeRange: options.timeRange || '7d', // 24h, 7d, 30d, 90d
      refreshInterval: options.refreshInterval || 30000, // 30 seconds
      darkMode: options.darkMode !== undefined ? options.darkMode : true,
      apiEndpoint: options.apiEndpoint || '/api/security-stats/history',
      onChartClick: options.onChartClick || null,
      enableExport: options.enableExport !== undefined ? options.enableExport : true,
      retryDelay: options.retryDelay || 3000, // 3 seconds
      maxRetries: options.maxRetries || 2 // Default max retries
    };

    // Chart data
    this.data = {
      scans: [],
      vulnerabilities: {
        critical: [],
        high: [],
        medium: [],
        low: []
      },
      successRate: [],
      securityScore: []
    };
    
    // Loading state
    this.isLoading = false;
    this.retryCount = 0;
    this.lastUpdateTime = null;

    // Initialize
    this.init();
  }

  /**
   * Initialize the charts component
   */
  init() {
    this.createChartContainer();
    this.loadChartData();
    
    // Set up refresh interval
    this.refreshInterval = setInterval(() => {
      this.loadChartData();
    }, this.options.refreshInterval);
    
    // Set up time range selector
    this.setupTimeRangeSelector();
  }

  /**
   * Create the chart container structure
   */
  createChartContainer() {
    this.container.innerHTML = `
      <div class="security-charts-container">
        <div class="charts-header">
          <h2>Security Statistics History</h2>
          <div class="time-range-selector">
            <button data-range="24h">24 Hours</button>
            <button data-range="7d" class="active">7 Days</button>
            <button data-range="30d">30 Days</button>
            <button data-range="90d">90 Days</button>
          </div>
        </div>
        <div class="charts-grid">
          <div class="chart-card" id="scans-chart-card">
            <h3>Scan Activity</h3>
            <div class="chart-container">
              <canvas id="scans-chart"></canvas>
              <div class="chart-loading">
                <div class="spinner"></div>
                <p>Loading data...</p>
              </div>
            </div>
          </div>
          <div class="chart-card" id="vulnerabilities-chart-card">
            <h3>Vulnerabilities Detected</h3>
            <div class="chart-container">
              <canvas id="vulnerabilities-chart"></canvas>
              <div class="chart-loading">
                <div class="spinner"></div>
                <p>Loading data...</p>
              </div>
            </div>
          </div>
          <div class="chart-card" id="success-rate-chart-card">
            <h3>Success Rate Trend</h3>
            <div class="chart-container">
              <canvas id="success-rate-chart"></canvas>
              <div class="chart-loading">
                <div class="spinner"></div>
                <p>Loading data...</p>
              </div>
            </div>
          </div>
          <div class="chart-card" id="security-score-chart-card">
            <h3>Overall Security Score</h3>
            <div class="chart-container">
              <canvas id="security-score-chart"></canvas>
              <div class="chart-loading">
                <div class="spinner"></div>
                <p>Loading data...</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Add styles
    if (!document.getElementById('security-charts-styles')) {
      const style = document.createElement('style');
      style.id = 'security-charts-styles';
      style.textContent = `
        .security-charts-container {
          font-family: 'Inter', 'Segoe UI', Roboto, Arial, sans-serif;
          color: #e0e0e0;
          background: rgba(20, 20, 35, 0.7);
          border-radius: 10px;
          padding: 20px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(100, 100, 255, 0.1);
        }

        .charts-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          flex-wrap: wrap;
        }

        .charts-header h2 {
          margin: 0;
          font-size: 1.5rem;
          font-weight: 600;
          color: #fff;
          margin-bottom: 10px;
        }

        .time-range-selector {
          display: flex;
          gap: 8px;
          margin-bottom: 10px;
        }

        .time-range-selector button {
          background: rgba(60, 60, 90, 0.3);
          border: 1px solid rgba(100, 100, 255, 0.2);
          color: #aaa;
          padding: 6px 12px;
          border-radius: 4px;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 0.85rem;
        }

        .time-range-selector button:hover {
          background: rgba(70, 70, 120, 0.4);
          color: #fff;
        }

        .time-range-selector button.active {
          background: rgba(80, 80, 255, 0.2);
          border-color: rgba(100, 100, 255, 0.5);
          color: #fff;
          box-shadow: 0 0 10px rgba(80, 80, 255, 0.2);
        }

        .charts-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 20px;
        }

        .chart-card {
          background: rgba(30, 30, 50, 0.5);
          border-radius: 8px;
          padding: 15px;
          box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
          border: 1px solid rgba(100, 100, 255, 0.1);
          transition: transform 0.2s, box-shadow 0.2s;
        }

        .chart-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
          border-color: rgba(100, 100, 255, 0.3);
        }

        .chart-card h3 {
          margin: 0 0 15px 0;
          font-size: 1.1rem;
          font-weight: 500;
          color: #ddd;
        }

        .chart-container {
          position: relative;
          height: 250px;
          width: 100%;
        }

        .chart-loading {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          background: rgba(30, 30, 50, 0.7);
          border-radius: 4px;
          z-index: 10;
        }

        .chart-loading.hidden {
          display: none;
        }

        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid rgba(100, 100, 255, 0.2);
          border-top-color: rgba(100, 100, 255, 0.8);
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin-bottom: 10px;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .chart-loading p {
          margin: 0;
          color: #aaa;
          font-size: 0.9rem;
        }

        @media (max-width: 768px) {
          .charts-grid {
            grid-template-columns: 1fr;
          }
          
          .charts-header {
            flex-direction: column;
            align-items: flex-start;
          }
        }
      `;
      document.head.appendChild(style);
    }
  }

  /**
   * Set up time range selector buttons
   */
  setupTimeRangeSelector() {
    const buttons = this.container.querySelectorAll('.time-range-selector button');
    buttons.forEach(button => {
      button.addEventListener('click', () => {
        // Update active button
        buttons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update time range and reload data
        this.options.timeRange = button.getAttribute('data-range');
        this.loadChartData();
      });
    });
  }

  /**
   * Load chart data from API or generate mock data
   */
  loadChartData() {
    // Show loading indicators
    this.toggleLoadingState(true);
    
    // Try to fetch from API with additional parameters
    fetch(`${this.options.apiEndpoint}?range=${this.options.timeRange}&darkMode=${this.options.darkMode}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`API request failed with status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        this.data = data;
        this.renderCharts();
        
        // Dispatch event that data was loaded successfully
        if (typeof CustomEvent === 'function') {
          const event = new CustomEvent('security-charts-updated', { 
            detail: { timeRange: this.options.timeRange, data: this.data }
          });
          this.container.dispatchEvent(event);
        }
      })
      .catch(error => {
        console.warn('Failed to fetch chart data, using mock data instead:', error);
        this.generateMockData();
        this.renderCharts();
      })
      .finally(() => {
        this.toggleLoadingState(false);
      });
  }

  /**
   * Generate mock data for charts
   */
  generateMockData() {
    const now = new Date();
    const dataPoints = this.getDataPointsForRange();
    
    // Clear existing data
    this.data = {
      scans: [],
      vulnerabilities: {
        critical: [],
        high: [],
        medium: [],
        low: []
      },
      successRate: [],
      securityScore: []
    };
    
    // Generate data points
    for (let i = 0; i < dataPoints; i++) {
      const date = new Date(now);
      date.setHours(date.getHours() - (dataPoints - i));
      
      // Scans data (total, web, network, system)
      const dailyScans = 10 + Math.floor(Math.random() * 15);
      this.data.scans.push({
        date: date.toISOString(),
        total: dailyScans,
        web: Math.floor(dailyScans * 0.5),
        network: Math.floor(dailyScans * 0.3),
        system: Math.floor(dailyScans * 0.2)
      });
      
      // Vulnerabilities data
      const criticalVulns = Math.floor(Math.random() * 3);
      const highVulns = Math.floor(Math.random() * 5);
      const mediumVulns = Math.floor(Math.random() * 8);
      const lowVulns = Math.floor(Math.random() * 12);
      
      this.data.vulnerabilities.critical.push({
        date: date.toISOString(),
        count: criticalVulns
      });
      
      this.data.vulnerabilities.high.push({
        date: date.toISOString(),
        count: highVulns
      });
      
      this.data.vulnerabilities.medium.push({
        date: date.toISOString(),
        count: mediumVulns
      });
      
      this.data.vulnerabilities.low.push({
        date: date.toISOString(),
        count: lowVulns
      });
      
      // Success rate data
      this.data.successRate.push({
        date: date.toISOString(),
        rate: 90 + Math.random() * 10
      });
      
      // Security score data (0-100)
      const baseScore = 75;
      const dayVariation = Math.sin(i / 5) * 10;
      const randomVariation = (Math.random() - 0.5) * 5;
      let score = baseScore + dayVariation + randomVariation;
      score = Math.min(100, Math.max(50, score));
      
      this.data.securityScore.push({
        date: date.toISOString(),
        score: score
      });
    }
  }

  /**
   * Get number of data points based on selected time range
   */
  getDataPointsForRange() {
    switch (this.options.timeRange) {
      case '24h': return 24;
      case '7d': return 7;
      case '30d': return 30;
      case '90d': return 90;
      default: return 7;
    }
  }

  /**
   * Toggle loading state for all charts
   */
  toggleLoadingState(isLoading) {
    const loadingElements = this.container.querySelectorAll('.chart-loading');
    loadingElements.forEach(el => {
      if (isLoading) {
        el.classList.remove('hidden');
      } else {
        el.classList.add('hidden');
      }
    });
  }

  /**
   * Render all charts with current data
   */
  renderCharts() {
    this.renderScansChart();
    this.renderVulnerabilitiesChart();
    this.renderSuccessRateChart();
    this.renderSecurityScoreChart();
  }

  /**
   * Render the scans activity chart
   */
  renderScansChart() {
    const canvas = document.getElementById('scans-chart');
    const ctx = canvas.getContext('2d');
    
    // Clear previous chart if it exists
    if (canvas.chart) {
      canvas.chart.destroy();
    }
    
    // Prepare data
    const labels = this.data.scans.map(item => {
      const date = new Date(item.date);
      return this.formatDateLabel(date);
    });
    
    const totalScans = this.data.scans.map(item => item.total);
    
    // Create chart
    canvas.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Total Scans',
          data: totalScans,
          borderColor: 'rgba(75, 192, 192, 1)',
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          borderWidth: 2,
          tension: 0.3,
          fill: true
        }]
      },
      options: this.getChartOptions('Scans')
    });
  }

  /**
   * Render the vulnerabilities chart
   */
  renderVulnerabilitiesChart() {
    const canvas = document.getElementById('vulnerabilities-chart');
    const ctx = canvas.getContext('2d');
    
    // Clear previous chart if it exists
    if (canvas.chart) {
      canvas.chart.destroy();
    }
    
    // Prepare data
    const labels = this.data.vulnerabilities.critical.map(item => {
      const date = new Date(item.date);
      return this.formatDateLabel(date);
    });
    
    const criticalData = this.data.vulnerabilities.critical.map(item => item.count);
    const highData = this.data.vulnerabilities.high.map(item => item.count);
    const mediumData = this.data.vulnerabilities.medium.map(item => item.count);
    const lowData = this.data.vulnerabilities.low.map(item => item.count);
    
    // Create chart
    canvas.chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Critical',
            data: criticalData,
            backgroundColor: 'rgba(255, 99, 132, 0.7)',
            borderColor: 'rgba(255, 99, 132, 1)',
            borderWidth: 1
          },
          {
            label: 'High',
            data: highData,
            backgroundColor: 'rgba(255, 159, 64, 0.7)',
            borderColor: 'rgba(255, 159, 64, 1)',
            borderWidth: 1
          },
          {
            label: 'Medium',
            data: mediumData,
            backgroundColor: 'rgba(255, 205, 86, 0.7)',
            borderColor: 'rgba(255, 205, 86, 1)',
            borderWidth: 1
          },
          {
            label: 'Low',
            data: lowData,
            backgroundColor: 'rgba(75, 192, 192, 0.7)',
            borderColor: 'rgba(75, 192, 192, 1)',
            borderWidth: 1
          }
        ]
      },
      options: this.getChartOptions('Vulnerabilities', true)
    });
  }

  /**
   * Render the success rate chart
   */
  renderSuccessRateChart() {
    const canvas = document.getElementById('success-rate-chart');
    const ctx = canvas.getContext('2d');
    
    // Clear previous chart if it exists
    if (canvas.chart) {
      canvas.chart.destroy();
    }
    
    // Prepare data
    const labels = this.data.successRate.map(item => {
      const date = new Date(item.date);
      return this.formatDateLabel(date);
    });
    
    const rateData = this.data.successRate.map(item => item.rate);
    
    // Create chart
    canvas.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Success Rate (%)',
          data: rateData,
          borderColor: 'rgba(54, 162, 235, 1)',
          backgroundColor: 'rgba(54, 162, 235, 0.2)',
          borderWidth: 2,
          tension: 0.3,
          fill: true
        }]
      },
      options: this.getChartOptions('Success Rate (%)', false, {
        min: Math.min(80, Math.min(...rateData) - 5),
        max: 100
      })
    });
  }

  /**
   * Render the security score chart
   */
  renderSecurityScoreChart() {
    const canvas = document.getElementById('security-score-chart');
    const ctx = canvas.getContext('2d');
    
    // Clear previous chart if it exists
    if (canvas.chart) {
      canvas.chart.destroy();
    }
    
    // Prepare data
    const labels = this.data.securityScore.map(item => {
      const date = new Date(item.date);
      return this.formatDateLabel(date);
    });
    
    const scoreData = this.data.securityScore.map(item => item.score);
    
    // Create gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(54, 215, 156, 1)');
    gradient.addColorStop(1, 'rgba(54, 215, 156, 0.1)');
    
    // Create chart
    canvas.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Security Score',
          data: scoreData,
          borderColor: 'rgba(54, 215, 156, 1)',
          backgroundColor: gradient,
          borderWidth: 2,
          tension: 0.3,
          fill: true
        }]
      },
      options: this.getChartOptions('Security Score', false, {
        min: Math.min(40, Math.min(...scoreData) - 10),
        max: 100
      })
    });
  }

  /**
   * Format date label based on time range
   */
  formatDateLabel(date) {
    switch (this.options.timeRange) {
      case '24h':
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      case '7d':
        return date.toLocaleDateString([], { weekday: 'short' });
      case '30d':
      case '90d':
        return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
      default:
        return date.toLocaleDateString();
    }
  }

  /**
   * Get common chart options
   */
  getChartOptions(label, isStacked = false, scales = {}) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#ddd',
            font: {
              size: 11
            }
          }
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          backgroundColor: 'rgba(20, 20, 35, 0.9)',
          titleColor: '#fff',
          bodyColor: '#ddd',
          borderColor: 'rgba(100, 100, 255, 0.3)',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          grid: {
            color: 'rgba(255, 255, 255, 0.05)'
          },
          ticks: {
            color: '#aaa',
            font: {
              size: 10
            }
          }
        },
        y: {
          stacked: isStacked,
          grid: {
            color: 'rgba(255, 255, 255, 0.05)'
          },
          ticks: {
            color: '#aaa',
            font: {
              size: 10
            }
          },
          ...scales
        }
      },
      interaction: {
        mode: 'nearest',
        axis: 'x',
        intersect: false
      },
      onClick: (event, elements) => {
        if (elements.length > 0 && typeof this.options.onChartClick === 'function') {
          const index = elements[0].index;
          this.options.onChartClick(label, index, this.data);
        }
      }
    };
  }

  /**
   * Clean up resources when component is no longer needed
   */
  destroy() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
    
    // Destroy all charts
    const canvases = this.container.querySelectorAll('canvas');
    canvases.forEach(canvas => {
      if (canvas.chart) {
        canvas.chart.destroy();
      }
    });
  }
  
  /**
   * Export chart data as CSV
   * @param {string} chartType - Type of chart to export (scans, vulnerabilities, successRate, securityScore)
   * @returns {string} CSV data URI or null if export fails
   */
  exportChartData(chartType) {
    if (!this.options.enableExport || !this.data) return null;
    
    let csvContent = 'data:text/csv;charset=utf-8,';
    let data = [];
    
    switch (chartType) {
      case 'scans':
        csvContent += 'Date,Total Scans,Web Scans,Network Scans,System Scans\n';
        data = this.data.scans.map(item => {
          return `${item.date},${item.total},${item.web},${item.network},${item.system}`;
        });
        break;
        
      case 'vulnerabilities':
        csvContent += 'Date,Critical,High,Medium,Low\n';
        // Assuming all vulnerability arrays have the same length and dates
        for (let i = 0; i < this.data.vulnerabilities.critical.length; i++) {
          const date = this.data.vulnerabilities.critical[i].date;
          const critical = this.data.vulnerabilities.critical[i].count;
          const high = this.data.vulnerabilities.high[i].count;
          const medium = this.data.vulnerabilities.medium[i].count;
          const low = this.data.vulnerabilities.low[i].count;
          data.push(`${date},${critical},${high},${medium},${low}`);
        }
        break;
        
      case 'successRate':
        csvContent += 'Date,Success Rate (%)\n';
        data = this.data.successRate.map(item => {
          return `${item.date},${item.rate}`;
        });
        break;
        
      case 'securityScore':
        csvContent += 'Date,Security Score\n';
        data = this.data.securityScore.map(item => {
          return `${item.date},${item.score}`;
        });
        break;
        
      default:
        return null;
    }
    
    csvContent += data.join('\n');
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `security_stats_${chartType}_${this.options.timeRange}_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    return encodedUri;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SecurityCharts;
}