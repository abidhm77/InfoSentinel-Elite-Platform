import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  InformationCircleIcon,
  XMarkIcon,
  BellIcon,
  ShieldExclamationIcon
} from '@heroicons/react/24/outline';
import '../styles/cyberpunk-design-system.css';

// Notification Context
const NotificationContext = createContext();

// Notification Types
const NOTIFICATION_TYPES = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
  SECURITY: 'security'
};

// Toast Component
function Toast({ notification, onDismiss }) {
  const { id, type, title, message, duration, persistent, actions } = notification;
  
  useEffect(() => {
    if (!persistent && duration > 0) {
      const timer = setTimeout(() => {
        onDismiss(id);
      }, duration);
      
      return () => clearTimeout(timer);
    }
  }, [id, duration, persistent, onDismiss]);

  const getIcon = () => {
    switch (type) {
      case NOTIFICATION_TYPES.SUCCESS:
        return CheckCircleIcon;
      case NOTIFICATION_TYPES.ERROR:
        return XCircleIcon;
      case NOTIFICATION_TYPES.WARNING:
        return ExclamationTriangleIcon;
      case NOTIFICATION_TYPES.SECURITY:
        return ShieldExclamationIcon;
      default:
        return InformationCircleIcon;
    }
  };

  const getColors = () => {
    switch (type) {
      case NOTIFICATION_TYPES.SUCCESS:
        return {
          bg: 'bg-success-green/10',
          border: 'border-success-green/30',
          text: 'text-success-green',
          icon: 'text-success-green'
        };
      case NOTIFICATION_TYPES.ERROR:
        return {
          bg: 'bg-critical-red/10',
          border: 'border-critical-red/30',
          text: 'text-critical-red',
          icon: 'text-critical-red'
        };
      case NOTIFICATION_TYPES.WARNING:
        return {
          bg: 'bg-high-orange/10',
          border: 'border-high-orange/30',
          text: 'text-high-orange',
          icon: 'text-high-orange'
        };
      case NOTIFICATION_TYPES.SECURITY:
        return {
          bg: 'bg-neon-purple/10',
          border: 'border-neon-purple/30',
          text: 'text-neon-purple',
          icon: 'text-neon-purple'
        };
      default:
        return {
          bg: 'bg-cyber-blue/10',
          border: 'border-cyber-blue/30',
          text: 'text-cyber-blue',
          icon: 'text-cyber-blue'
        };
    }
  };

  const Icon = getIcon();
  const colors = getColors();

  return (
    <motion.div
      initial={{ opacity: 0, x: 300, scale: 0.8 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 300, scale: 0.8 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className={`glass-strong p-4 rounded-xl border-l-4 ${colors.bg} ${colors.border} max-w-md w-full shadow-lg`}
    >
      <div className="flex items-start space-x-3">
        <div className={`flex-shrink-0 ${colors.icon}`}>
          <Icon className="w-6 h-6" />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              {title && (
                <h4 className={`text-sm font-semibold ${colors.text} mb-1`}>
                  {title}
                </h4>
              )}
              <p className="text-sm text-text-secondary">{message}</p>
            </div>
            
            <button
              onClick={() => onDismiss(id)}
              className="flex-shrink-0 ml-2 text-text-tertiary hover:text-text-primary transition-colors"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
          
          {actions && actions.length > 0 && (
            <div className="mt-3 flex space-x-2">
              {actions.map((action, index) => (
                <button
                  key={index}
                  onClick={() => {
                    action.handler();
                    if (action.dismissOnClick) {
                      onDismiss(id);
                    }
                  }}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                    action.primary
                      ? `bg-${colors.text.split('-')[1]}-${colors.text.split('-')[2]} text-bg-primary hover:opacity-80`
                      : `text-${colors.text} hover:bg-${colors.text.split('-')[1]}-${colors.text.split('-')[2]}/10`
                  }`}
                >
                  {action.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
      
      {!persistent && duration > 0 && (
        <motion.div
          className={`absolute bottom-0 left-0 h-1 ${colors.bg.replace('/10', '')}`}
          initial={{ width: '100%' }}
          animate={{ width: '0%' }}
          transition={{ duration: duration / 1000, ease: 'linear' }}
        />
      )}
    </motion.div>
  );
}

// Alert Banner Component
function AlertBanner({ alert, onDismiss }) {
  const { id, type, title, message, dismissible = true, actions } = alert;
  
  const getColors = () => {
    switch (type) {
      case NOTIFICATION_TYPES.ERROR:
        return {
          bg: 'bg-critical-red/20',
          border: 'border-critical-red',
          text: 'text-critical-red'
        };
      case NOTIFICATION_TYPES.WARNING:
        return {
          bg: 'bg-high-orange/20',
          border: 'border-high-orange',
          text: 'text-high-orange'
        };
      case NOTIFICATION_TYPES.SECURITY:
        return {
          bg: 'bg-neon-purple/20',
          border: 'border-neon-purple',
          text: 'text-neon-purple'
        };
      default:
        return {
          bg: 'bg-cyber-blue/20',
          border: 'border-cyber-blue',
          text: 'text-cyber-blue'
        };
    }
  };

  const colors = getColors();

  return (
    <motion.div
      initial={{ opacity: 0, y: -50 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -50 }}
      className={`${colors.bg} border ${colors.border} rounded-lg p-4 mb-4`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <BellIcon className={`w-5 h-5 ${colors.text}`} />
          <div>
            {title && (
              <h3 className={`font-semibold text-sm ${colors.text} mb-1`}>
                {title}
              </h3>
            )}
            <p className="text-sm text-text-primary">{message}</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          {actions && actions.map((action, index) => (
            <button
              key={index}
              onClick={action.handler}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                action.primary
                  ? `bg-${colors.text.split('-')[1]}-${colors.text.split('-')[2]} text-bg-primary hover:opacity-80`
                  : `text-${colors.text} hover:bg-${colors.text.split('-')[1]}-${colors.text.split('-')[2]}/10`
              }`}
            >
              {action.label}
            </button>
          ))}
          
          {dismissible && (
            <button
              onClick={() => onDismiss(id)}
              className="text-text-tertiary hover:text-text-primary transition-colors ml-2"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// Toast Container
function ToastContainer({ notifications, onDismiss }) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-md">
      <AnimatePresence>
        {notifications.map((notification) => (
          <Toast
            key={notification.id}
            notification={notification}
            onDismiss={onDismiss}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}

// Alert Container
function AlertContainer({ alerts, onDismiss }) {
  return (
    <div className="space-y-2">
      <AnimatePresence>
        {alerts.map((alert) => (
          <AlertBanner
            key={alert.id}
            alert={alert}
            onDismiss={onDismiss}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}

// Notification Provider
export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const addNotification = useCallback((notification) => {
    const id = Date.now() + Math.random();
    const newNotification = {
      id,
      duration: 5000,
      persistent: false,
      ...notification
    };
    
    setNotifications(prev => [...prev, newNotification]);
    return id;
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(notification => notification.id !== id));
  }, []);

  const addAlert = useCallback((alert) => {
    const id = Date.now() + Math.random();
    const newAlert = {
      id,
      dismissible: true,
      ...alert
    };
    
    setAlerts(prev => [...prev, newAlert]);
    return id;
  }, []);

  const removeAlert = useCallback((id) => {
    setAlerts(prev => prev.filter(alert => alert.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
    setAlerts([]);
  }, []);

  // Convenience methods
  const success = useCallback((message, options = {}) => {
    return addNotification({
      type: NOTIFICATION_TYPES.SUCCESS,
      message,
      ...options
    });
  }, [addNotification]);

  const error = useCallback((message, options = {}) => {
    return addNotification({
      type: NOTIFICATION_TYPES.ERROR,
      message,
      persistent: true,
      ...options
    });
  }, [addNotification]);

  const warning = useCallback((message, options = {}) => {
    return addNotification({
      type: NOTIFICATION_TYPES.WARNING,
      message,
      duration: 8000,
      ...options
    });
  }, [addNotification]);

  const info = useCallback((message, options = {}) => {
    return addNotification({
      type: NOTIFICATION_TYPES.INFO,
      message,
      ...options
    });
  }, [addNotification]);

  const security = useCallback((message, options = {}) => {
    return addNotification({
      type: NOTIFICATION_TYPES.SECURITY,
      message,
      persistent: true,
      ...options
    });
  }, [addNotification]);

  const securityAlert = useCallback((message, options = {}) => {
    return addAlert({
      type: NOTIFICATION_TYPES.SECURITY,
      message,
      ...options
    });
  }, [addAlert]);

  const value = {
    notifications,
    alerts,
    addNotification,
    removeNotification,
    addAlert,
    removeAlert,
    clearAll,
    success,
    error,
    warning,
    info,
    security,
    securityAlert
  };

  return (
    <NotificationContext.Provider value={value}>
      {children}
      <ToastContainer 
        notifications={notifications} 
        onDismiss={removeNotification} 
      />
    </NotificationContext.Provider>
  );
}

// Hook to use notifications
export function useNotifications() {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  return context;
}

// Alert Container Component (for use in layouts)
export function AlertsContainer() {
  const { alerts, removeAlert } = useNotifications();
  
  return (
    <AlertContainer alerts={alerts} onDismiss={removeAlert} />
  );
}

// Export types for convenience
export { NOTIFICATION_TYPES };

// Example usage component
export function NotificationDemo() {
  const notifications = useNotifications();

  const handleSuccess = () => {
    notifications.success('Scan completed successfully!', {
      title: 'Success',
      actions: [
        {
          label: 'View Results',
          handler: () => console.log('View results clicked'),
          primary: true,
          dismissOnClick: true
        }
      ]
    });
  };

  const handleError = () => {
    notifications.error('Failed to connect to target server', {
      title: 'Connection Error',
      actions: [
        {
          label: 'Retry',
          handler: () => console.log('Retry clicked'),
          primary: true
        },
        {
          label: 'Cancel',
          handler: () => console.log('Cancel clicked'),
          dismissOnClick: true
        }
      ]
    });
  };

  const handleWarning = () => {
    notifications.warning('SSL certificate expires in 7 days', {
      title: 'Certificate Warning'
    });
  };

  const handleSecurity = () => {
    notifications.security('Critical vulnerability detected in login system', {
      title: 'Security Alert',
      actions: [
        {
          label: 'Investigate',
          handler: () => console.log('Investigate clicked'),
          primary: true
        }
      ]
    });
  };

  const handleSecurityAlert = () => {
    notifications.securityAlert('Multiple failed login attempts detected from IP 192.168.1.100', {
      title: 'Security Incident',
      actions: [
        {
          label: 'Block IP',
          handler: () => console.log('Block IP clicked'),
          primary: true
        },
        {
          label: 'View Details',
          handler: () => console.log('View details clicked')
        }
      ]
    });
  };

  return (
    <div className="space-y-4 p-6">
      <h2 className="text-heading font-semibold gradient-text mb-4">Notification System Demo</h2>
      <div className="flex flex-wrap gap-4">
        <button onClick={handleSuccess} className="btn-cyber px-4 py-2 text-sm">
          Success Notification
        </button>
        <button onClick={handleError} className="btn-ghost px-4 py-2 text-sm">
          Error Notification
        </button>
        <button onClick={handleWarning} className="btn-ghost px-4 py-2 text-sm">
          Warning Notification
        </button>
        <button onClick={handleSecurity} className="btn-ghost px-4 py-2 text-sm">
          Security Notification
        </button>
        <button onClick={handleSecurityAlert} className="btn-ghost px-4 py-2 text-sm">
          Security Alert
        </button>
      </div>
    </div>
  );
}