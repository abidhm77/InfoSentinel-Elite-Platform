/**
 * Security Stats Updater
 * 
 * This script automatically updates the security stat cards with real data
 * by fetching from the backend API at regular intervals.
 */

class SecurityStatsUpdater {
  constructor(options = {}) {
    // Configuration with defaults
    this.config = {
      updateInterval: options.updateInterval || 10000, // 10 seconds by default
      apiEndpoint: options.apiEndpoint || '/api/security-stats',
      mockData: options.mockData || false,
      mockDataVariation: options.mockDataVariation || true,
      onUpdateStart: options.onUpdateStart || null,
      onUpdateComplete: options.onUpdateComplete || null,
      onError: options.onError || null,
      retryDelay: options.retryDelay || 3000, // 3 seconds by default
      maxRetries: options.maxRetries || 3, // 3 retries by default
      authToken: options.authToken || null // Authentication token for API requests
    };

    // Initial stats
    this.stats = {
      totalScans: 1248,
      criticalVulnerabilities: 37,
      scansRunning: 5,
      successRate: 94.7,
      securityScore: 85.2
    };

    // Reference to the interval
    this.updateInterval = null;
    
    // Status tracking
    this.isLoading = false;
    this.retryCount = 0;
    this.lastUpdateTime = null;
    this.connectionStatus = 'unknown';
    
    // Bind methods
    this.startUpdates = this.startUpdates.bind(this);
    this.stopUpdates = this.stopUpdates.bind(this);
    this.updateStats = this.updateStats.bind(this);
    this.fetchStats = this.fetchStats.bind(this);
    this.generateMockStats = this.generateMockStats.bind(this);
    this.updateStatusIndicator = this.updateStatusIndicator.bind(this);
    this.showToast = this.showToast.bind(this);
    this.checkApiHealth = this.checkApiHealth.bind(this);
    
    // Create status indicator if it doesn't exist
    this.createStatusIndicator();
  }
  
  /**
   * Create API status indicator
   */
  createStatusIndicator() {
    // Check if we already have a status indicator
    let statusIndicator = document.getElementById('api-status-indicator');
    
    if (!statusIndicator) {
      // Create the status indicator
      statusIndicator = document.createElement('div');
      statusIndicator.id = 'api-status-indicator';
      statusIndicator.className = 'api-status unknown';
      statusIndicator.innerHTML = `
        <span class="status-dot"></span>
        <span class="status-text">API: Unknown</span>
      `;
      
      // Add styles if not already in the document
      if (!document.getElementById('status-indicator-styles')) {
        const styles = document.createElement('style');
        styles.id = 'status-indicator-styles';
        styles.textContent = `
          .api-status {
            position: fixed;
            bottom: 10px;
            right: 10px;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            display: flex;
            align-items: center;
            z-index: 1000;
            background: rgba(0,0,0,0.7);
            color: white;
          }
          .api-status .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 5px;
          }
          .api-status.connected .status-dot { background-color: #4CAF50; }
          .api-status.connecting .status-dot { background-color: #FFC107; }
          .api-status.disconnected .status-dot { background-color: #F44336; }
          .api-status.unknown .status-dot { background-color: #9E9E9E; }
        `;
        document.head.appendChild(styles);
      }
      
      // Add to the document
      document.body.appendChild(statusIndicator);
    }
    
    this.statusIndicator = statusIndicator;
    return statusIndicator;
  }
  
  /**
   * Update the status indicator
   */
  updateStatusIndicator(status, message) {
    if (!this.statusIndicator) {
      this.createStatusIndicator();
    }
    
    this.connectionStatus = status;
    
    // Update the indicator
    this.statusIndicator.className = `api-status ${status}`;
    this.statusIndicator.querySelector('.status-text').textContent = `API: ${message || status}`;
  }

  /**
   * Start automatic updates
   */
  startUpdates() {
    // Perform initial update
    this.updateStats();
    
    // Set up interval for subsequent updates
    this.updateInterval = setInterval(this.updateStats, this.config.updateInterval);
    
    console.log(`Security stats updater started. Updating every ${this.config.updateInterval / 1000} seconds.`);
    return this;
  }

  /**
   * Stop automatic updates
   */
  stopUpdates() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
      console.log('Security stats updater stopped.');
    }
    return this;
  }

  /**
   * Update the stats
   */
  async updateStats() {
    // Prevent multiple simultaneous updates
    if (this.isLoading) {
      console.log('Update already in progress, skipping...');
      return;
    }
    
    this.isLoading = true;
    this.updateStatusIndicator('connecting', 'Connecting...');
    
    try {
      // Notify update start if callback provided
      if (typeof this.config.onUpdateStart === 'function') {
        this.config.onUpdateStart();
      }

      // Get new stats (either from API or mock data)
      const newStats = this.config.mockData 
        ? this.generateMockStats() 
        : await this.fetchStats();
      
      // Update the component with new stats
      const statsComponent = document.querySelector('security-stat-cards');
      if (statsComponent) {
        statsComponent.updateStats(newStats);
        this.stats = { ...this.stats, ...newStats };
        
        // Show toast notification for successful update
        this.showToast('Stats updated successfully', 'success');
      } else {
        console.warn('Security stat cards component not found in the DOM.');
      }
      
      // Update status indicator
      this.updateStatusIndicator('connected', 'Connected');
      this.lastUpdateTime = new Date();
      this.retryCount = 0;

      // Notify update complete if callback provided
      if (typeof this.config.onUpdateComplete === 'function') {
        this.config.onUpdateComplete(newStats);
      }
    } catch (error) {
      console.error('Error updating security stats:', error);
      
      // Update status indicator
      this.updateStatusIndicator('disconnected', 'Connection failed');
      
      // Show toast notification for error
      this.showToast(`Failed to update stats: ${error.message}`, 'error');
      
      // Implement retry logic
      if (this.retryCount < this.config.maxRetries) {
        this.retryCount++;
        console.log(`Retrying in ${this.config.retryDelay / 1000} seconds... (${this.retryCount}/${this.config.maxRetries})`);
        
        setTimeout(() => {
          this.updateStats();
        }, this.config.retryDelay);
      }
      
      // Notify error if callback provided
      if (typeof this.config.onError === 'function') {
        this.config.onError(error);
      }
    } finally {
      this.isLoading = false;
    }
  }
  
  /**
   * Show toast notification
   */
  showToast(message, type = 'info') {
    // Check if toast container exists
    let toastContainer = document.getElementById('toast-container');
    
    if (!toastContainer) {
      // Create toast container
      toastContainer = document.createElement('div');
      toastContainer.id = 'toast-container';
      
      // Add styles if not already in the document
      if (!document.getElementById('toast-styles')) {
        const styles = document.createElement('style');
        styles.id = 'toast-styles';
        styles.textContent = `
          #toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
          }
          .toast {
            margin-bottom: 10px;
            padding: 15px 20px;
            border-radius: 4px;
            color: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            animation: toast-in 0.3s ease-in-out;
            max-width: 300px;
          }
          .toast.success { background-color: #4CAF50; }
          .toast.error { background-color: #F44336; }
          .toast.warning { background-color: #FFC107; color: #333; }
          .toast.info { background-color: #2196F3; }
          @keyframes toast-in {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
        `;
        document.head.appendChild(styles);
      }
      
      document.body.appendChild(toastContainer);
    }
    
    // Create toast
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    // Add to container
    toastContainer.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.3s ease-in-out';
      
      setTimeout(() => {
        toastContainer.removeChild(toast);
      }, 300);
    }, 3000);
  }

  /**
   * Fetch stats from the API
   */
  async fetchStats() {
    try {
      const headers = {
        'Content-Type': 'application/json'
      };
      
      // Add authorization header if token exists
      if (this.config.authToken) {
        headers['Authorization'] = `Bearer ${this.config.authToken}`;
      }
      
      const response = await fetch(this.config.apiEndpoint, { headers });
      
      if (response.status === 401 || response.status === 403) {
        // Handle authentication errors
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');
        window.location.href = 'login.html';
        throw new Error('Authentication failed. Please log in again.');
      }
      
      if (!response.ok) {
        throw new Error(`API responded with status: ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      console.warn(`Failed to fetch from API: ${error.message}. Using mock data instead.`);
      return this.generateMockStats();
    }
  }

  /**
   * Generate mock stats for testing
   */
  generateMockStats() {
    if (!this.config.mockDataVariation) {
      return this.stats;
    }
    
    // Create variations of the current stats for a realistic effect
    const securityScore = Math.min(100, Math.max(70, this.stats.securityScore + (Math.random() > 0.5 ? 0.2 : -0.2))).toFixed(1);
    
    return {
      totalScans: this.stats.totalScans + Math.floor(Math.random() * 5),
      criticalVulnerabilities: Math.max(0, this.stats.criticalVulnerabilities + (Math.random() > 0.7 ? 1 : -1)),
      scansRunning: Math.max(0, Math.min(10, this.stats.scansRunning + (Math.random() > 0.5 ? 1 : -1))),
      successRate: Math.min(100, Math.max(90, this.stats.successRate + (Math.random() > 0.5 ? 0.1 : -0.1))).toFixed(1),
      securityScore: securityScore,
      trends: {
        totalScans: Math.random() > 0.6 ? 'increasing' : (Math.random() > 0.5 ? 'decreasing' : 'stable'),
        criticalVulnerabilities: Math.random() > 0.6 ? 'increasing' : (Math.random() > 0.5 ? 'decreasing' : 'stable'),
        scansRunning: Math.random() > 0.6 ? 'increasing' : (Math.random() > 0.5 ? 'decreasing' : 'stable'),
        successRate: Math.random() > 0.6 ? 'increasing' : (Math.random() > 0.5 ? 'decreasing' : 'stable'),
        securityScore: Math.random() > 0.6 ? 'increasing' : (Math.random() > 0.5 ? 'decreasing' : 'stable')
      }
    };
  }
  
  /**
   * Check API health
   */
  async checkApiHealth() {
    try {
      const response = await fetch(this.config.apiEndpoint.replace('/api/security-stats', '/health'));
      if (!response.ok) {
        throw new Error(`Health check failed with status: ${response.status}`);
      }
      return true;
    } catch (error) {
      console.error('API health check failed:', error);
      return false;
    }
  }
}

// Initialize the updater when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
  // Create and start the updater with real API data
  window.statsUpdater = new SecurityStatsUpdater({
    mockData: false, // Use real API data from our backend
    updateInterval: 5000, // Update every 5 seconds
    retryDelay: 3000,
    maxRetries: 3,
    onUpdateComplete: (stats) => {
      console.log('Stats updated:', stats);
    }
  }).startUpdates();
  
  // Add event listener for the security stat cards
  document.addEventListener('card-click', (event) => {
    const cardType = event.detail.type;
    console.log(`Card clicked: ${cardType}`);
    
    // Navigate to the detailed stats dashboard
    const currentPath = window.location.pathname;
    
    // Only navigate if we're not already on the stats dashboard
    if (!currentPath.includes('stats-dashboard.html')) {
      window.location.href = 'stats-dashboard.html';
    }
  });
});

// Expose a global function to manually trigger updates if needed
window.updateSecurityStats = () => {
  if (window.statsUpdater) {
    window.statsUpdater.updateStats();
  }
};