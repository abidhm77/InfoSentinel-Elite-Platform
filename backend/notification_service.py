import random
import datetime
import uuid
from flask import jsonify

class NotificationService:
    def __init__(self):
        self.notifications = []
        self.generate_initial_notifications()
        
    def get_all_notifications(self):
        """Return all notifications"""
        return jsonify(self.notifications)
    
    def get_notifications_since(self, notification_id):
        """Return all notifications newer than the given ID"""
        if not notification_id:
            return jsonify(self.notifications[:10])  # Return most recent 10 if no ID provided
            
        # Find the index of the notification with the given ID
        index = next((i for i, n in enumerate(self.notifications) if n['id'] == notification_id), None)
        
        if index is None:
            return jsonify([])  # ID not found
            
        # Return all notifications newer than the given ID
        return jsonify(self.notifications[:index])
    
    def mark_as_read(self, notification_id):
        """Mark a notification as read"""
        notification = next((n for n in self.notifications if n['id'] == notification_id), None)
        if notification:
            notification['read'] = True
            return jsonify(notification)
        return jsonify({"error": "Notification not found"}), 404
    
    def toggle_read_status(self, notification_id, read_status):
        """Toggle the read status of a notification"""
        notification = next((n for n in self.notifications if n['id'] == notification_id), None)
        if notification:
            notification['read'] = read_status
            return jsonify(notification)
        return jsonify({"error": "Notification not found"}), 404
    
    def mark_all_as_read(self):
        """Mark all notifications as read"""
        for notification in self.notifications:
            notification['read'] = True
        return jsonify({"success": True})
    
    def clear_all_notifications(self):
        """Clear all notifications"""
        self.notifications = []
        return jsonify({"success": True})
    
    def generate_new_notification(self):
        """Generate a new notification and add it to the list"""
        types = ['security', 'system', 'user', 'info']
        security_messages = [
            'Suspicious login attempt detected',
            'Firewall blocked potential attack',
            'New vulnerability detected in system',
            'Security scan completed',
            'Unusual network activity detected'
        ]
        system_messages = [
            'System update available',
            'Database backup completed',
            'Server performance degraded',
            'Disk space running low',
            'Service restarted successfully'
        ]
        user_messages = [
            'New user registered',
            'User password changed',
            'User role updated',
            'User account locked',
            'User session expired'
        ]
        info_messages = [
            'Weekly report generated',
            'New feature available',
            'Scheduled maintenance upcoming',
            'License will expire soon',
            'Documentation updated'
        ]
        
        type_index = random.randint(0, len(types) - 1)
        type_value = types[type_index]
        
        message = ""
        if type_value == 'security':
            message = security_messages[random.randint(0, len(security_messages) - 1)]
        elif type_value == 'system':
            message = system_messages[random.randint(0, len(system_messages) - 1)]
        elif type_value == 'user':
            message = user_messages[random.randint(0, len(user_messages) - 1)]
        else:
            message = info_messages[random.randint(0, len(info_messages) - 1)]
        
        notification = {
            'id': str(uuid.uuid4()),
            'type': type_value,
            'message': message,
            'timestamp': datetime.datetime.now().isoformat(),
            'read': False,
            'link': self.generate_link(type_value)
        }
        
        # Add to the beginning of the list (newest first)
        self.notifications.insert(0, notification)
        
        # Limit the number of notifications to 100
        if len(self.notifications) > 100:
            self.notifications = self.notifications[:100]
            
        return notification
    
    def generate_link(self, type_value):
        """Generate a link based on notification type"""
        if type_value == 'security':
            return 'vulnerabilities.html'
        elif type_value == 'system':
            return 'stats-dashboard.html'
        elif type_value == 'user':
            return '#'
        else:
            return 'index.html'
    
    def generate_initial_notifications(self):
        """Generate some initial notifications"""
        # Generate 5 initial notifications
        for _ in range(5):
            self.generate_new_notification()
            
        # Mark some as read
        for i in range(len(self.notifications)):
            if i % 2 == 0:  # Mark every other notification as read
                self.notifications[i]['read'] = True