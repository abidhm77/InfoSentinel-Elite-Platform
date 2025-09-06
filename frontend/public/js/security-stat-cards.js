class SecurityStatCards extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    
    // Sample data - would be replaced with real data in production
    this.stats = {
      totalScans: 1248,
      criticalVulnerabilities: 37,
      scansRunning: 5,
      successRate: 94.7
    };
  }

  connectedCallback() {
    this.render();
    this.setupCounters();
    this.setupInteractions();
  }

  render() {
    const template = document.createElement('template');
    template.innerHTML = `
      <style>
        :host {
          --card-bg: rgba(16, 20, 34, 0.65);
          --card-border: rgba(255, 255, 255, 0.08);
          --card-radius: 16px;
          --text-primary: #e6edf3;
          --text-secondary: #a1adc0;
          
          /* Theme colors */
          --neutral-glow: rgba(99, 179, 237, 0.25);
          --success-glow: rgba(72, 187, 120, 0.3);
          --warning-glow: rgba(237, 137, 54, 0.3);
          --critical-glow: rgba(229, 62, 62, 0.35);
          
          /* Card themes */
          --total-color: #63b3ed;
          --critical-color: #e53e3e;
          --running-color: #ed8936;
          --success-color: #48bb78;
          
          /* Animation speeds */
          --hover-transition: 280ms cubic-bezier(0.2, 0.8, 0.2, 1);
          
          display: block;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .stats-container {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
          gap: 20px;
          padding: 10px;
        }
        
        .stat-card {
          position: relative;
          padding: 24px;
          border-radius: var(--card-radius);
          background: linear-gradient(180deg, 
            rgba(30, 41, 59, 0.8), 
            rgba(15, 23, 42, 0.75));
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border: 1px solid var(--card-border);
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
          overflow: hidden;
          transition: transform var(--hover-transition),
                      box-shadow var(--hover-transition);
        }
        
        .stat-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
        }
        
        /* Card themes */
        .stat-card.total {
          border-top: 2px solid var(--total-color);
          box-shadow: 0 0 20px var(--neutral-glow);
        }
        .stat-card.total:hover {
          box-shadow: 0 0 30px var(--neutral-glow);
        }
        
        .stat-card.critical {
          border-top: 2px solid var(--critical-color);
          box-shadow: 0 0 20px var(--critical-glow);
        }
        .stat-card.critical:hover {
          box-shadow: 0 0 30px var(--critical-glow);
        }
        
        .stat-card.running {
          border-top: 2px solid var(--running-color);
          box-shadow: 0 0 20px var(--warning-glow);
        }
        .stat-card.running:hover {
          box-shadow: 0 0 30px var(--warning-glow);
        }
        
        .stat-card.success {
          border-top: 2px solid var(--success-color);
          box-shadow: 0 0 20px var(--success-glow);
        }
        .stat-card.success:hover {
          box-shadow: 0 0 30px var(--success-glow);
        }
        
        .card-title {
          font-size: 0.9rem;
          font-weight: 500;
          color: var(--text-secondary);
          margin: 0 0 8px 0;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        
        .card-icon {
          display: inline-flex;
          width: 20px;
          height: 20px;
        }
        
        .card-value {
          font-size: 2.5rem;
          font-weight: 700;
          margin: 0;
          color: var(--text-primary);
          line-height: 1.2;
          display: flex;
          align-items: baseline;
          gap: 4px;
        }
        
        .card-value .unit {
          font-size: 1.2rem;
          font-weight: 500;
          opacity: 0.7;
        }
        
        .card-trend {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-top: 12px;
          font-size: 0.85rem;
        }
        
        .trend-up {
          color: var(--success-color);
        }
        
        .trend-down {
          color: var(--critical-color);
        }
        
        /* Loading animation */
        .loading-bar {
          height: 4px;
          width: 100%;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 4px;
          margin-top: 12px;
          overflow: hidden;
        }
        
        .loading-progress {
          height: 100%;
          width: 30%;
          background: linear-gradient(90deg, 
            var(--running-color), 
            rgba(237, 137, 54, 0.7));
          border-radius: 4px;
          animation: loading 1.5s infinite;
          box-shadow: 0 0 10px var(--warning-glow);
        }
        
        @keyframes loading {
          0% {
            transform: translateX(-100%);
          }
          100% {
            transform: translateX(400%);
          }
        }
        
        /* Circular progress for success rate */
        .progress-ring {
          position: relative;
          width: 80px;
          height: 80px;
          margin-top: 10px;
        }
        
        .progress-ring-circle {
          transform: rotate(-90deg);
          transform-origin: 50% 50%;
          stroke-linecap: round;
          transition: stroke-dashoffset 1s ease;
        }
        
        .progress-ring-text {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          font-size: 1.2rem;
          font-weight: 700;
          color: var(--text-primary);
        }
        
        /* Pulse effect for critical vulnerabilities */
        .pulse {
          position: absolute;
          top: 20px;
          right: 20px;
          width: 12px;
          height: 12px;
          border-radius: 50%;
          background-color: var(--critical-color);
          box-shadow: 0 0 0 rgba(229, 62, 62, 0.4);
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0% {
            box-shadow: 0 0 0 0 rgba(229, 62, 62, 0.4);
          }
          70% {
            box-shadow: 0 0 0 10px rgba(229, 62, 62, 0);
          }
          100% {
            box-shadow: 0 0 0 0 rgba(229, 62, 62, 0);
          }
        }
        
        /* Tooltip */
        .tooltip {
          position: absolute;
          bottom: 100%;
          left: 50%;
          transform: translateX(-50%) translateY(-10px);
          background: rgba(15, 23, 42, 0.95);
          color: var(--text-primary);
          padding: 8px 12px;
          border-radius: 6px;
          font-size: 0.85rem;
          pointer-events: none;
          opacity: 0;
          transition: opacity 0.3s, transform 0.3s;
          white-space: nowrap;
          z-index: 10;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
          border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .stat-card:hover .tooltip {
          opacity: 1;
          transform: translateX(-50%) translateY(0);
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
          .stats-container {
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
          }
          
          .card-value {
            font-size: 2rem;
          }
        }
        
        @media (max-width: 480px) {
          .stats-container {
            grid-template-columns: 1fr;
          }
        }
      </style>
      
      <div class="stats-container">
        <!-- Total Scans Card -->
        <div class="stat-card total" tabindex="0">
          <div class="tooltip">View all scan history</div>
          <h3 class="card-title">
            <span class="card-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
              </svg>
            </span>
            Total Scans
          </h3>
          <p class="card-value">
            <span class="counter" data-target="${this.stats.totalScans}">0</span>
          </p>
          <div class="card-trend trend-up">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="18 15 12 9 6 15"></polyline>
            </svg>
            <span>12% from last month</span>
          </div>
        </div>
        
        <!-- Critical Vulnerabilities Card -->
        <div class="stat-card critical" tabindex="0">
          <div class="tooltip">View critical security issues</div>
          <div class="pulse"></div>
          <h3 class="card-title">
            <span class="card-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
              </svg>
            </span>
            Critical Vulnerabilities
          </h3>
          <p class="card-value">
            <span class="counter" data-target="${this.stats.criticalVulnerabilities}">0</span>
          </p>
          <div class="card-trend trend-down">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="6 9 12 15 18 9"></polyline>
            </svg>
            <span>5% from last week</span>
          </div>
        </div>
        
        <!-- Scans Running Card -->
        <div class="stat-card running" tabindex="0">
          <div class="tooltip">View active scans in progress</div>
          <h3 class="card-title">
            <span class="card-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
            </span>
            Scans Running
          </h3>
          <p class="card-value">
            <span class="counter" data-target="${this.stats.scansRunning}">0</span>
          </p>
          <div class="loading-bar">
            <div class="loading-progress"></div>
          </div>
        </div>
        
        <!-- Success Rate Card -->
        <div class="stat-card success" tabindex="0">
          <div class="tooltip">View scan success metrics</div>
          <h3 class="card-title">
            <span class="card-icon">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
              </svg>
            </span>
            Success Rate
          </h3>
          <p class="card-value">
            <span class="counter" data-target="${this.stats.successRate}">0</span>
            <span class="unit">%</span>
          </p>
          <div class="progress-ring">
            <svg width="80" height="80">
              <circle
                class="progress-ring-circle-bg"
                stroke="rgba(255, 255, 255, 0.1)"
                stroke-width="6"
                fill="transparent"
                r="34"
                cx="40"
                cy="40"
              />
              <circle
                class="progress-ring-circle"
                stroke="var(--success-color)"
                stroke-width="6"
                fill="transparent"
                r="34"
                cx="40"
                cy="40"
                stroke-dasharray="213.52"
                stroke-dashoffset="213.52"
              />
            </svg>
            <div class="progress-ring-text"></div>
          </div>
        </div>
      </div>
    `;
    
    this.shadowRoot.appendChild(template.content.cloneNode(true));
  }
  
  setupCounters() {
    const counters = this.shadowRoot.querySelectorAll('.counter');
    const duration = 2000; // Animation duration in milliseconds
    
    counters.forEach(counter => {
      const target = +counter.getAttribute('data-target');
      const increment = target / (duration / 16); // Update every ~16ms for 60fps
      
      let currentCount = 0;
      const updateCounter = () => {
        currentCount += increment;
        
        if (currentCount < target) {
          counter.textContent = Math.ceil(currentCount);
          requestAnimationFrame(updateCounter);
        } else {
          counter.textContent = target;
        }
      };
      
      updateCounter();
    });
    
    // Setup circular progress for success rate
    const circle = this.shadowRoot.querySelector('.progress-ring-circle');
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    
    circle.style.strokeDasharray = `${circumference} ${circumference}`;
    circle.style.strokeDashoffset = circumference;
    
    const progressText = this.shadowRoot.querySelector('.progress-ring-text');
    const successRate = this.stats.successRate;
    
    // Animate the progress ring
    let progress = 0;
    const animateProgress = () => {
      progress += 1;
      
      if (progress <= successRate) {
        const offset = circumference - (progress / 100) * circumference;
        circle.style.strokeDashoffset = offset;
        progressText.textContent = `${Math.round(progress)}%`;
        requestAnimationFrame(animateProgress);
      } else {
        progressText.textContent = `${successRate}%`;
      }
    };
    
    setTimeout(() => {
      animateProgress();
    }, 500);
  }
  
  setupInteractions() {
    const cards = this.shadowRoot.querySelectorAll('.stat-card');
    
    cards.forEach(card => {
      // Add click interaction
      card.addEventListener('click', () => {
        // Simulate an action when clicked
        const cardType = Array.from(card.classList)
          .find(cls => ['total', 'critical', 'running', 'success'].includes(cls));
        
        // Dispatch custom event that can be listened to by parent application
        const event = new CustomEvent('card-click', {
          bubbles: true,
          composed: true,
          detail: { type: cardType }
        });
        
        this.dispatchEvent(event);
        
        // Visual feedback on click
        card.style.transform = 'scale(0.98) translateY(-2px)';
        setTimeout(() => {
          card.style.transform = '';
        }, 150);
        
        // Show detailed view based on card type
        this._showDetailedView(cardType);
      });
      
      // Keyboard accessibility
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          card.click();
        }
      });
    });
  }
  
  // Show detailed information when a card is clicked
  _showDetailedView(cardType) {
    // Create modal content based on card type
    let title, content;
    
    switch(cardType) {
      case 'total':
        title = 'Total Scans Details';
        content = `
          <div class="detail-content">
            <p>Total scans performed: <strong>${this.stats.totalScans}</strong></p>
            <div class="detail-breakdown">
              <div class="breakdown-item">
                <span class="breakdown-label">Web Scans:</span>
                <span class="breakdown-value">${Math.floor(this.stats.totalScans * 0.45)}</span>
              </div>
              <div class="breakdown-item">
                <span class="breakdown-label">Network Scans:</span>
                <span class="breakdown-value">${Math.floor(this.stats.totalScans * 0.35)}</span>
              </div>
              <div class="breakdown-item">
                <span class="breakdown-label">System Scans:</span>
                <span class="breakdown-value">${Math.floor(this.stats.totalScans * 0.2)}</span>
              </div>
            </div>
            <p class="detail-note">Click on "View All Scans" to see complete scan history.</p>
          </div>
        `;
        break;
      case 'critical':
        title = 'Critical Vulnerabilities';
        content = `
          <div class="detail-content">
            <p>Critical vulnerabilities detected: <strong>${this.stats.criticalVulnerabilities}</strong></p>
            <div class="detail-breakdown">
              <div class="breakdown-item critical">
                <span class="breakdown-label">High Severity:</span>
                <span class="breakdown-value">${Math.floor(this.stats.criticalVulnerabilities * 0.6)}</span>
              </div>
              <div class="breakdown-item medium">
                <span class="breakdown-label">Medium Severity:</span>
                <span class="breakdown-value">${Math.floor(this.stats.criticalVulnerabilities * 0.3)}</span>
              </div>
              <div class="breakdown-item low">
                <span class="breakdown-label">Low Severity:</span>
                <span class="breakdown-value">${Math.floor(this.stats.criticalVulnerabilities * 0.1)}</span>
              </div>
            </div>
            <p class="detail-note">Click on "View Vulnerabilities Report" for detailed analysis.</p>
          </div>
        `;
        break;
      case 'running':
        title = 'Scans In Progress';
        content = `
          <div class="detail-content">
            <p>Currently running scans: <strong>${this.stats.scansRunning}</strong></p>
            <div class="scan-progress">
              ${Array(this.stats.scansRunning).fill().map((_, i) => `
                <div class="scan-item">
                  <div class="scan-info">
                    <span class="scan-name">Scan #${1000 + i}</span>
                    <span class="scan-target">Target: 192.168.1.${10 + i}</span>
                  </div>
                  <div class="progress-bar">
                    <div class="progress" style="width: ${Math.floor(Math.random() * 100)}%"></div>
                  </div>
                </div>
              `).join('')}
            </div>
            <p class="detail-note">Click on "View Active Scans" to monitor progress.</p>
          </div>
        `;
        break;
      case 'success':
        title = 'Success Rate Analysis';
        content = `
          <div class="detail-content">
            <p>Overall success rate: <strong>${this.stats.successRate}%</strong></p>
            <div class="success-chart">
              <div class="chart-bar">
                <div class="chart-fill" style="width: ${this.stats.successRate}%"></div>
              </div>
              <div class="chart-labels">
                <span>0%</span>
                <span>50%</span>
                <span>100%</span>
              </div>
            </div>
            <div class="detail-breakdown">
              <div class="breakdown-item">
                <span class="breakdown-label">Successful Scans:</span>
                <span class="breakdown-value">${Math.floor(this.stats.totalScans * (this.stats.successRate/100))}</span>
              </div>
              <div class="breakdown-item">
                <span class="breakdown-label">Failed Scans:</span>
                <span class="breakdown-value">${Math.floor(this.stats.totalScans * (1 - this.stats.successRate/100))}</span>
              </div>
            </div>
            <p class="detail-note">Click on "View Success Metrics" for trend analysis.</p>
          </div>
        `;
        break;
    }
    
    // Create and show modal
    this._showModal(title, content);
  }
  
  // Create and display a modal with the detailed information
  _showModal(title, content) {
    // Check if modal already exists and remove it
    const existingModal = document.querySelector('.stat-detail-modal');
    if (existingModal) {
      existingModal.remove();
    }
    
    // Create modal elements
    const modal = document.createElement('div');
    modal.className = 'stat-detail-modal';
    
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h2>${title}</h2>
          <button class="close-button">&times;</button>
        </div>
        <div class="modal-body">
          ${content}
        </div>
        <div class="modal-footer">
          <button class="action-button">View Details</button>
          <button class="close-button-secondary">Close</button>
        </div>
      </div>
    `;
    
    // Add modal to document body
    document.body.appendChild(modal);
    
    // Add modal styles to document head if not already added
    if (!document.querySelector('#modal-styles')) {
      const style = document.createElement('style');
      style.id = 'modal-styles';
      style.textContent = `
        .stat-detail-modal {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background-color: rgba(0, 0, 0, 0.7);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
          animation: fadeIn 0.3s ease-out;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        .modal-content {
          background: rgba(30, 30, 40, 0.95);
          border: 1px solid rgba(100, 100, 255, 0.3);
          border-radius: 8px;
          width: 90%;
          max-width: 600px;
          max-height: 90vh;
          overflow-y: auto;
          box-shadow: 0 0 20px rgba(50, 50, 255, 0.3);
          animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
          from { transform: translateY(-20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
        
        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 15px 20px;
          border-bottom: 1px solid rgba(100, 100, 255, 0.2);
        }
        
        .modal-header h2 {
          color: #fff;
          margin: 0;
          font-size: 1.5rem;
        }
        
        .close-button {
          background: none;
          border: none;
          color: #aaa;
          font-size: 1.5rem;
          cursor: pointer;
          transition: color 0.2s;
        }
        
        .close-button:hover {
          color: #fff;
        }
        
        .modal-body {
          padding: 20px;
          color: #ddd;
        }
        
        .modal-footer {
          display: flex;
          justify-content: flex-end;
          padding: 15px 20px;
          border-top: 1px solid rgba(100, 100, 255, 0.2);
        }
        
        .action-button {
          background: linear-gradient(to right, #4a4af7, #2c2cf0);
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          margin-right: 10px;
          transition: all 0.2s;
        }
        
        .action-button:hover {
          background: linear-gradient(to right, #5a5aff, #3a3aff);
          box-shadow: 0 0 10px rgba(90, 90, 255, 0.5);
        }
        
        .close-button-secondary {
          background: rgba(80, 80, 100, 0.3);
          color: #ddd;
          border: 1px solid rgba(100, 100, 255, 0.2);
          padding: 8px 16px;
          border-radius: 4px;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .close-button-secondary:hover {
          background: rgba(90, 90, 120, 0.4);
          color: #fff;
        }
        
        .detail-content {
          font-size: 0.95rem;
          line-height: 1.5;
        }
        
        .detail-breakdown {
          margin: 15px 0;
          background: rgba(40, 40, 60, 0.5);
          border-radius: 6px;
          padding: 10px;
        }
        
        .breakdown-item {
          display: flex;
          justify-content: space-between;
          padding: 8px 10px;
          border-bottom: 1px solid rgba(100, 100, 255, 0.1);
        }
        
        .breakdown-item:last-child {
          border-bottom: none;
        }
        
        .breakdown-item.critical .breakdown-value {
          color: #ff5252;
        }
        
        .breakdown-item.medium .breakdown-value {
          color: #ffaa00;
        }
        
        .breakdown-item.low .breakdown-value {
          color: #2196f3;
        }
        
        .detail-note {
          font-style: italic;
          color: #aaa;
          margin-top: 15px;
          font-size: 0.9rem;
        }
        
        .scan-progress {
          margin: 15px 0;
        }
        
        .scan-item {
          margin-bottom: 10px;
          background: rgba(40, 40, 60, 0.5);
          border-radius: 6px;
          padding: 10px;
        }
        
        .scan-info {
          display: flex;
          justify-content: space-between;
          margin-bottom: 5px;
        }
        
        .progress-bar {
          height: 8px;
          background: rgba(100, 100, 255, 0.1);
          border-radius: 4px;
          overflow: hidden;
        }
        
        .progress {
          height: 100%;
          background: linear-gradient(to right, #4a4af7, #2c2cf0);
          border-radius: 4px;
        }
        
        .success-chart {
          margin: 15px 0;
        }
        
        .chart-bar {
          height: 20px;
          background: rgba(40, 40, 60, 0.5);
          border-radius: 10px;
          overflow: hidden;
        }
        
        .chart-fill {
          height: 100%;
          background: linear-gradient(to right, #4CAF50, #8BC34A);
          border-radius: 10px 0 0 10px;
        }
        
        .chart-labels {
          display: flex;
          justify-content: space-between;
          margin-top: 5px;
          color: #aaa;
          font-size: 0.8rem;
        }
        
        @media (max-width: 600px) {
          .modal-content {
            width: 95%;
          }
          
          .modal-header h2 {
            font-size: 1.2rem;
          }
        }
      `;
      document.head.appendChild(style);
    }
    
    // Add event listeners for close buttons
    const closeButtons = modal.querySelectorAll('.close-button, .close-button-secondary');
    closeButtons.forEach(button => {
      button.addEventListener('click', () => {
        modal.classList.add('fade-out');
        setTimeout(() => {
          modal.remove();
        }, 300);
      });
    });
    
    // Close modal when clicking outside content
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.add('fade-out');
        setTimeout(() => {
          modal.remove();
        }, 300);
      }
    });
    
    // Add action button event listener
    const actionButton = modal.querySelector('.action-button');
    actionButton.addEventListener('click', () => {
      console.log(`Action button clicked for ${title}`);
      // Here you would typically navigate to a detailed view
      // For now, just close the modal
      modal.classList.add('fade-out');
      setTimeout(() => {
        modal.remove();
      }, 300);
    });
  }
  
  // Public method to update stats
  updateStats(newStats) {
    // Update internal data
    this.stats = { ...this.stats, ...newStats };
    
    // Update displayed values
    const counters = this.shadowRoot.querySelectorAll('.counter');
    counters.forEach(counter => {
      const type = counter.closest('.stat-card').classList[1];
      let value;
      
      switch(type) {
        case 'total':
          value = this.stats.totalScans;
          break;
        case 'critical':
          value = this.stats.criticalVulnerabilities;
          break;
        case 'running':
          value = this.stats.scansRunning;
          break;
        case 'success':
          value = this.stats.successRate;
          break;
      }
      
      counter.setAttribute('data-target', value);
      counter.textContent = value;
      
      // Update success rate circle if needed
      if (type === 'success') {
        const circle = this.shadowRoot.querySelector('.progress-ring-circle');
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;
        const offset = circumference - (value / 100) * circumference;
        
        circle.style.strokeDashoffset = offset;
        this.shadowRoot.querySelector('.progress-ring-text').textContent = `${value}%`;
      }
    });
  }
}

// Define the custom element
customElements.define('security-stat-cards', SecurityStatCards);

// Example usage:
// <security-stat-cards></security-stat-cards>
// 
// To update stats programmatically:
// document.querySelector('security-stat-cards').updateStats({
//   totalScans: 1500,
//   criticalVulnerabilities: 25,
//   scansRunning: 8,
//   successRate: 96.2
// });