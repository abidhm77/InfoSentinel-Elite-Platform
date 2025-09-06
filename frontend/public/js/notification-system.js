/**
 * InfoSentinel Real-Time Notification System
 * Provides real-time notifications for security events and system alerts
 */
class NotificationSystem {
    constructor(options = {}) {
        // Configuration
        this.config = {
            apiEndpoint: options.apiEndpoint || '/api/notifications',
            pollInterval: options.pollInterval || 10000, // Default: 10 seconds
            authToken: options.authToken || localStorage.getItem('auth_token'),
            maxNotifications: options.maxNotifications || 50,
            onNewNotification: options.onNewNotification || null,
            useMockData: options.useMockData !== undefined ? options.useMockData : false
        };
        
        // State
        this.notifications = [];
        this.unreadCount = 0;
        this.lastNotificationId = null;
        
        // DOM Elements
        this.elements = {
            notificationBell: document.getElementById('notification-bell'),
            notificationBadge: document.getElementById('notification-badge'),
            notificationDropdown: document.getElementById('notification-dropdown'),
            notificationList: document.getElementById('notification-list'),
            markAllReadBtn: document.getElementById('mark-all-read'),
            clearAllBtn: document.getElementById('clear-all'),
            generateNotificationBtn: document.getElementById('generate-notification')
        };
        
        // Initialize
        this.init();
    }
    
    init() {
        // Initialize event listeners
        this.initEventListeners();
        
        // Start polling for notifications
        this.startPolling();
        
        // Initial fetch
        this.fetchNotifications();
    }
    
    initEventListeners() {
        // Toggle dropdown when bell is clicked
        if (this.elements.notificationBell) {
            this.elements.notificationBell.addEventListener('click', () => {
                this.toggleDropdown();
            });
        }
        
        // Mark all as read
        if (this.elements.markAllReadBtn) {
            this.elements.markAllReadBtn.addEventListener('click', () => {
                this.markAllAsRead();
            });
        }
        
        // Clear all notifications
        if (this.elements.clearAllBtn) {
            this.elements.clearAllBtn.addEventListener('click', () => {
                this.clearAllNotifications();
            });
        }
        
        // Generate test notification
        if (this.elements.generateNotificationBtn) {
            this.elements.generateNotificationBtn.addEventListener('click', () => {
                this.generateTestNotification();
            });
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (event) => {
            if (this.elements.notificationDropdown && 
                this.elements.notificationDropdown.classList.contains('show') && 
                !this.elements.notificationBell.contains(event.target) && 
                !this.elements.notificationDropdown.contains(event.target)) {
                this.elements.notificationDropdown.classList.remove('show');
            }
        });
    }
    
    startPolling() {
        // Poll for new notifications at the configured interval
        setInterval(() => {
            this.fetchNotifications();
        }, this.config.pollInterval);
    }
    
    fetchNotifications() {
        if (this.config.useMockData) {
            // Use mock data for testing
            this.handleNotifications(this.generateMockNotifications());
            return;
        }
        
        // Fetch from API
        const url = this.lastNotificationId 
            ? `${this.config.apiEndpoint}/since/${this.lastNotificationId}`
            : this.config.apiEndpoint;
            
        fetch(url, {
            headers: {
                'Authorization': `Bearer ${this.config.authToken}`
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch notifications');
            }
            return response.json();
        })
        .then(data => {
            this.handleNotifications(data);
        })
        .catch(error => {
            console.error('Error fetching notifications:', error);
        });
    }
    
    handleNotifications(notifications) {
        if (!notifications || notifications.length === 0) {
            return;
        }
        
        // Update last notification ID
        const latestNotification = notifications.reduce((latest, current) => {
            return current.id > latest.id ? current : latest;
        }, notifications[0]);
        
        this.lastNotificationId = latestNotification.id;
        
        // Add new notifications to the list
        const newNotifications = notifications.filter(notification => {
            return !this.notifications.some(n => n.id === notification.id);
        });
        
        if (newNotifications.length > 0) {
            // Add to the beginning of the array
            this.notifications = [...newNotifications, ...this.notifications]
                .slice(0, this.config.maxNotifications);
            
            // Update unread count
            this.updateUnreadCount();
            
            // Render notifications
            this.renderNotifications();
            
            // Show browser notification for new notifications
            newNotifications.forEach(notification => {
                this.showBrowserNotification(notification);
                
                // Call onNewNotification callback if provided
                if (this.config.onNewNotification) {
                    this.config.onNewNotification(notification);
                }
            });
        }
    }
    
    renderNotifications() {
        if (!this.elements.notificationList) {
            return;
        }
        
        // Clear current list
        this.elements.notificationList.innerHTML = '';
        
        if (this.notifications.length === 0) {
            const emptyItem = document.createElement('li');
            emptyItem.className = 'dropdown-item text-center text-muted';
            emptyItem.textContent = 'No notifications';
            this.elements.notificationList.appendChild(emptyItem);
            return;
        }
        
        // Add notifications to the list
        this.notifications.forEach(notification => {
            const item = document.createElement('li');
            item.className = `notification-item dropdown-item ${notification.read ? 'read' : 'unread'}`;
            item.dataset.id = notification.id;
            
            const icon = this.getNotificationIcon(notification.type);
            const timeAgo = this.timeAgo(notification.timestamp);
            
            item.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="notification-icon me-3">
                        ${icon}
                    </div>
                    <div class="notification-content flex-grow-1">
                        <div class="notification-title">${notification.title}</div>
                        <div class="notification-message">${notification.message}</div>
                        <div class="notification-time text-muted small">${timeAgo}</div>
                    </div>
                </div>
            `;
            
            // Mark as read when clicked
            item.addEventListener('click', () => {
                this.markAsRead(notification.id);
            });
            
            this.elements.notificationList.appendChild(item);
        });
    }
    
    updateUnreadCount() {
        this.unreadCount = this.notifications.filter(n => !n.read).length;
        
        if (this.elements.notificationBadge) {
            if (this.unreadCount > 0) {
                this.elements.notificationBadge.textContent = this.unreadCount > 99 ? '99+' : this.unreadCount;
                this.elements.notificationBadge.classList.remove('d-none');
            } else {
                this.elements.notificationBadge.classList.add('d-none');
            }
        }
    }
    
    markAsRead(notificationId) {
        if (this.config.useMockData) {
            // Update local state for mock data
            this.notifications = this.notifications.map(n => {
                if (n.id === notificationId) {
                    return { ...n, read: true };
                }
                return n;
            });
            
            this.updateUnreadCount();
            this.renderNotifications();
            return;
        }
        
        // Call API to mark as read
        fetch(`${this.config.apiEndpoint}/${notificationId}/read`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${this.config.authToken}`,
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to mark notification as read');
            }
            return response.json();
        })
        .then(() => {
            // Update local state
            this.notifications = this.notifications.map(n => {
                if (n.id === notificationId) {
                    return { ...n, read: true };
                }
                return n;
            });
            
            this.updateUnreadCount();
            this.renderNotifications();
        })
        .catch(error => {
            console.error('Error marking notification as read:', error);
        });
    }
    
    markAllAsRead() {
        if (this.config.useMockData) {
            // Update local state for mock data
            this.notifications = this.notifications.map(n => ({ ...n, read: true }));
            this.updateUnreadCount();
            this.renderNotifications();
            return;
        }
        
        // Call API to mark all as read
        fetch(`${this.config.apiEndpoint}/read/all`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${this.config.authToken}`,
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to mark all notifications as read');
            }
            return response.json();
        })
        .then(() => {
            // Update local state
            this.notifications = this.notifications.map(n => ({ ...n, read: true }));
            this.updateUnreadCount();
            this.renderNotifications();
        })
        .catch(error => {
            console.error('Error marking all notifications as read:', error);
        });
    }
    
    clearAllNotifications() {
        if (this.config.useMockData) {
            // Clear local state for mock data
            this.notifications = [];
            this.updateUnreadCount();
            this.renderNotifications();
            return;
        }
        
        // Call API to clear all notifications
        fetch(`${this.config.apiEndpoint}/clear`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${this.config.authToken}`
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to clear notifications');
            }
            return response.json();
        })
        .then(() => {
            // Clear local state
            this.notifications = [];
            this.updateUnreadCount();
            this.renderNotifications();
        })
        .catch(error => {
            console.error('Error clearing notifications:', error);
        });
    }
    
    generateTestNotification() {
        if (this.config.useMockData) {
            // Generate mock notification
            const mockNotification = this.generateMockNotifications(1)[0];
            this.handleNotifications([mockNotification]);
            return;
        }
        
        // Call API to generate a test notification
        fetch(`${this.config.apiEndpoint}/generate`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.config.authToken}`,
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to generate test notification');
            }
            return response.json();
        })
        .then(data => {
            // Fetch notifications to get the new one
            this.fetchNotifications();
        })
        .catch(error => {
            console.error('Error generating test notification:', error);
        });
    }
    
    showBrowserNotification(notification) {
        // Check if browser notifications are supported and permitted
        if (!("Notification" in window)) {
            return;
        }
        
        if (Notification.permission === "granted") {
            this.createBrowserNotification(notification);
        } else if (Notification.permission !== "denied") {
            Notification.requestPermission().then(permission => {
                if (permission === "granted") {
                    this.createBrowserNotification(notification);
                }
            });
        }
    }
    
    createBrowserNotification(notification) {
        const options = {
            body: notification.message,
            icon: '/public/img/logo.png'
        };
        
        const browserNotification = new Notification(notification.title, options);
        
        browserNotification.onclick = () => {
            window.focus();
            this.markAsRead(notification.id);
            if (this.elements.notificationDropdown) {
                this.elements.notificationDropdown.classList.add('show');
            }
        };
    }
    
    toggleDropdown() {
        if (this.elements.notificationDropdown) {
            this.elements.notificationDropdown.classList.toggle('show');
        }
    }
    
    // Helper methods
    getNotificationIcon(type) {
        const iconMap = {
            'security': '<i class="fas fa-shield-alt text-danger"></i>',
            'system': '<i class="fas fa-server text-primary"></i>',
            'user': '<i class="fas fa-user text-success"></i>',
            'info': '<i class="fas fa-info-circle text-info"></i>',
            'warning': '<i class="fas fa-exclamation-triangle text-warning"></i>'
        };
        
        return iconMap[type] || iconMap.info;
    }
    
    timeAgo(timestamp) {
        const now = new Date();
        const date = new Date(timestamp);
        const seconds = Math.floor((now - date) / 1000);
        
        let interval = Math.floor(seconds / 31536000);
        if (interval >= 1) {
            return interval + " year" + (interval === 1 ? "" : "s") + " ago";
        }
        
        interval = Math.floor(seconds / 2592000);
        if (interval >= 1) {
            return interval + " month" + (interval === 1 ? "" : "s") + " ago";
        }
        
        interval = Math.floor(seconds / 86400);
        if (interval >= 1) {
            return interval + " day" + (interval === 1 ? "" : "s") + " ago";
        }
        
        interval = Math.floor(seconds / 3600);
        if (interval >= 1) {
            return interval + " hour" + (interval === 1 ? "" : "s") + " ago";
        }
        
        interval = Math.floor(seconds / 60);
        if (interval >= 1) {
            return interval + " minute" + (interval === 1 ? "" : "s") + " ago";
        }
        
        return "just now";
    }
    
    // Mock data generation for testing
    generateMockNotifications(count = 5) {
        const types = ['security', 'system', 'user', 'info', 'warning'];
        const titles = {
            'security': ['Security Alert', 'Vulnerability Detected', 'Intrusion Attempt', 'Suspicious Activity'],
            'system': ['System Update', 'Server Restart', 'Maintenance Scheduled', 'Performance Issue'],
            'user': ['User Login', 'Password Changed', 'Profile Updated', 'New User Registered'],
            'info': ['Information Update', 'New Feature Available', 'Documentation Updated', 'API Change'],
            'warning': ['Warning', 'Resource Limit', 'Certificate Expiring', 'Disk Space Low']
        };
        
        const messages = {
            'security': [
                'Potential SQL injection attempt detected from IP 192.168.1.45',
                'Multiple failed login attempts for user admin',
                'Unusual file access pattern detected in /var/www/html',
                'Firewall blocked suspicious outbound connection to 203.0.113.42'
            ],
            'system': [
                'System update completed successfully. Restart recommended.',
                'Database server performance degraded. Check query optimization.',
                'Scheduled maintenance will begin in 30 minutes.',
                'CPU usage exceeded 90% for 5 minutes.'
            ],
            'user': [
                'User john.doe logged in from a new device',
                'Password changed for user sarah.smith',
                'User profile updated with new contact information',
                'New user account created: james.wilson'
            ],
            'info': [
                'New dashboard features are now available',
                'API documentation has been updated',
                'System report for August is ready for review',
                'New security best practices guide published'
            ],
            'warning': [
                'SSL certificate will expire in 15 days',
                'Disk space usage at 85% on primary server',
                'API rate limit approaching threshold',
                'Backup job failed to complete last night'
            ]
        };
        
        return Array.from({ length: count }, (_, i) => {
            const type = types[Math.floor(Math.random() * types.length)];
            const titleArray = titles[type];
            const messageArray = messages[type];
            
            return {
                id: Date.now() + i,
                type: type,
                title: titleArray[Math.floor(Math.random() * titleArray.length)],
                message: messageArray[Math.floor(Math.random() * messageArray.length)],
                timestamp: new Date(Date.now() - Math.floor(Math.random() * 86400000)).toISOString(),
                read: false
            };
        });
    }
}