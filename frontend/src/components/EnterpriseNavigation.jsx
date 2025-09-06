import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  BellIcon,
  UserCircleIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  BookmarkIcon,
  ClockIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import '../styles/cyberpunk-design-system.css';

// Breadcrumb Component
function Breadcrumb({ path }) {
  const breadcrumbs = [
    { name: 'InfoSentinel', href: '/', current: false },
    ...path.map((item, index) => ({
      ...item,
      current: index === path.length - 1
    }))
  ];

  return (
    <nav className="flex" aria-label="Breadcrumb">
      <ol className="flex items-center space-x-2">
        {breadcrumbs.map((breadcrumb, index) => (
          <li key={breadcrumb.name} className="flex items-center">
            {index > 0 && (
              <ChevronRightIcon className="w-4 h-4 text-text-tertiary mx-2" />
            )}
            <motion.a
              href={breadcrumb.href}
              className={`text-sm font-medium transition-colors duration-200 ${
                breadcrumb.current
                  ? 'text-cyber-blue'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
              whileHover={{ scale: 1.05 }}
            >
              {breadcrumb.name}
            </motion.a>
          </li>
        ))}
      </ol>
    </nav>
  );
}

// Global Search Component
function GlobalSearch({ isOpen, onClose }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [recentSearches] = useState([
    'SQL injection vulnerabilities',
    'Network scan results',
    'Critical security alerts',
    'Compliance reports'
  ]);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    if (query.length > 2) {
      // Simulate search results
      const mockResults = [
        { type: 'Vulnerability', title: 'SQL Injection in Login Form', category: 'Critical' },
        { type: 'Scan', title: 'Network Scan - 192.168.1.0/24', category: 'Completed' },
        { type: 'Report', title: 'Monthly Security Assessment', category: 'Executive' },
        { type: 'Alert', title: 'Suspicious Activity Detected', category: 'High Priority' }
      ].filter(item => 
        item.title.toLowerCase().includes(query.toLowerCase())
      );
      setResults(mockResults);
    } else {
      setResults([]);
    }
  }, [query]);

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: -20 }}
        className="absolute top-20 left-1/2 transform -translate-x-1/2 w-full max-w-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="glass-strong p-6 rounded-2xl mx-4">
          {/* Search Input */}
          <div className="relative mb-6">
            <MagnifyingGlassIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-text-tertiary" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search vulnerabilities, scans, reports..."
              className="w-full pl-12 pr-12 py-4 bg-bg-glass border border-cyber-blue/30 rounded-xl text-text-primary placeholder-text-tertiary focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/20 transition-all duration-300"
            />
            <button
              onClick={onClose}
              className="absolute right-4 top-1/2 transform -translate-y-1/2 text-text-tertiary hover:text-text-primary transition-colors"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          {/* Search Results */}
          {query.length > 2 && results.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-medium text-text-secondary mb-3">Search Results</h3>
              <div className="space-y-2">
                {results.map((result, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="p-3 bg-bg-glass-subtle rounded-lg hover:bg-bg-glass cursor-pointer transition-colors duration-200"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium text-text-primary">{result.title}</div>
                        <div className="text-sm text-text-secondary">{result.type}</div>
                      </div>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        result.category === 'Critical' ? 'bg-critical-red/20 text-critical-red' :
                        result.category === 'High Priority' ? 'bg-high-orange/20 text-high-orange' :
                        'bg-cyber-blue/20 text-cyber-blue'
                      }`}>
                        {result.category}
                      </span>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}

          {/* Recent Searches */}
          {query.length === 0 && (
            <div>
              <h3 className="text-sm font-medium text-text-secondary mb-3 flex items-center">
                <ClockIcon className="w-4 h-4 mr-2" />
                Recent Searches
              </h3>
              <div className="space-y-2">
                {recentSearches.map((search, index) => (
                  <motion.button
                    key={index}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                    onClick={() => setQuery(search)}
                    className="w-full text-left p-3 bg-bg-glass-subtle rounded-lg hover:bg-bg-glass transition-colors duration-200 text-text-secondary hover:text-text-primary"
                  >
                    {search}
                  </motion.button>
                ))}
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}

// Notification Panel
function NotificationPanel({ isOpen, onClose }) {
  const [notifications] = useState([
    {
      id: 1,
      type: 'critical',
      title: 'Critical Vulnerability Detected',
      message: 'SQL injection vulnerability found in login system',
      time: '2 minutes ago',
      read: false
    },
    {
      id: 2,
      type: 'warning',
      title: 'Scan Completed',
      message: 'Network scan of 192.168.1.0/24 completed with 3 findings',
      time: '15 minutes ago',
      read: false
    },
    {
      id: 3,
      type: 'info',
      title: 'Report Generated',
      message: 'Monthly security assessment report is ready',
      time: '1 hour ago',
      read: true
    }
  ]);

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="absolute top-full right-0 mt-2 w-96 glass-strong rounded-xl p-4 z-50"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-heading font-semibold gradient-text">Notifications</h3>
        <button
          onClick={onClose}
          className="text-text-tertiary hover:text-text-primary transition-colors"
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {notifications.map((notification) => (
          <motion.div
            key={notification.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`p-3 rounded-lg border-l-4 cursor-pointer transition-all duration-200 hover:bg-bg-glass-subtle ${
              notification.type === 'critical' ? 'border-critical-red bg-critical-red/5' :
              notification.type === 'warning' ? 'border-high-orange bg-high-orange/5' :
              'border-cyber-blue bg-cyber-blue/5'
            } ${!notification.read ? 'opacity-100' : 'opacity-70'}`}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className={`font-medium text-sm ${
                  notification.type === 'critical' ? 'text-critical-red' :
                  notification.type === 'warning' ? 'text-high-orange' :
                  'text-cyber-blue'
                }`}>
                  {notification.title}
                </div>
                <div className="text-text-secondary text-xs mt-1">
                  {notification.message}
                </div>
                <div className="text-text-tertiary text-xs mt-2">
                  {notification.time}
                </div>
              </div>
              {!notification.read && (
                <div className="w-2 h-2 bg-cyber-blue rounded-full mt-1" />
              )}
            </div>
          </motion.div>
        ))}
      </div>

      <div className="mt-4 pt-3 border-t border-bg-tertiary">
        <button className="w-full text-center text-sm text-cyber-blue hover:text-cyber-blue/80 transition-colors">
          View All Notifications
        </button>
      </div>
    </motion.div>
  );
}

// User Menu
function UserMenu({ isOpen, onClose }) {
  const menuItems = [
    { icon: UserCircleIcon, label: 'Profile Settings', href: '/profile' },
    { icon: Cog6ToothIcon, label: 'System Preferences', href: '/settings' },
    { icon: BookmarkIcon, label: 'Saved Searches', href: '/saved' },
    { icon: ArrowRightOnRectangleIcon, label: 'Sign Out', href: '/logout', danger: true }
  ];

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 10 }}
      className="absolute top-full right-0 mt-2 w-64 glass-strong rounded-xl p-2 z-50"
    >
      <div className="p-3 border-b border-bg-tertiary">
        <div className="font-medium text-text-primary">Security Admin</div>
        <div className="text-sm text-text-secondary">admin@infosentinel.net</div>
      </div>

      <div className="py-2">
        {menuItems.map((item, index) => (
          <motion.a
            key={index}
            href={item.href}
            className={`flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors duration-200 ${
              item.danger
                ? 'text-critical-red hover:bg-critical-red/10'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-glass'
            }`}
            whileHover={{ x: 5 }}
          >
            <item.icon className="w-5 h-5" />
            <span className="text-sm font-medium">{item.label}</span>
          </motion.a>
        ))}
      </div>
    </motion.div>
  );
}

// Main Enterprise Navigation Component
export default function EnterpriseNavigation({ currentPath = [], onNavigate }) {
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [unreadCount] = useState(2);

  return (
    <>
      {/* Top Navigation Bar */}
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        className="bg-bg-secondary/95 backdrop-blur-xl border-b border-cyber-blue/20 px-6 py-4"
      >
        <div className="flex items-center justify-between">
          {/* Left Section - Breadcrumbs */}
          <div className="flex items-center space-x-6">
            <Breadcrumb path={currentPath} />
          </div>

          {/* Right Section - Actions */}
          <div className="flex items-center space-x-4">
            {/* Global Search */}
            <motion.button
              onClick={() => setIsSearchOpen(true)}
              className="p-2 text-text-secondary hover:text-text-primary transition-colors duration-200 relative"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <MagnifyingGlassIcon className="w-6 h-6" />
            </motion.button>

            {/* Filters */}
            <motion.button
              className="p-2 text-text-secondary hover:text-text-primary transition-colors duration-200"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <FunnelIcon className="w-6 h-6" />
            </motion.button>

            {/* Notifications */}
            <div className="relative">
              <motion.button
                onClick={() => setIsNotificationOpen(!isNotificationOpen)}
                className="p-2 text-text-secondary hover:text-text-primary transition-colors duration-200 relative"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <BellIcon className="w-6 h-6" />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-5 h-5 bg-critical-red text-white text-xs rounded-full flex items-center justify-center font-medium">
                    {unreadCount}
                  </span>
                )}
              </motion.button>
              <NotificationPanel 
                isOpen={isNotificationOpen} 
                onClose={() => setIsNotificationOpen(false)} 
              />
            </div>

            {/* User Menu */}
            <div className="relative">
              <motion.button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center space-x-2 p-2 text-text-secondary hover:text-text-primary transition-colors duration-200"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <div className="w-8 h-8 bg-gradient-to-r from-cyber-blue to-neon-purple rounded-full flex items-center justify-center">
                  <UserCircleIcon className="w-5 h-5 text-white" />
                </div>
                <ChevronDownIcon className="w-4 h-4" />
              </motion.button>
              <UserMenu 
                isOpen={isUserMenuOpen} 
                onClose={() => setIsUserMenuOpen(false)} 
              />
            </div>
          </div>
        </div>
      </motion.div>

      {/* Global Search Modal */}
      <AnimatePresence>
        <GlobalSearch 
          isOpen={isSearchOpen} 
          onClose={() => setIsSearchOpen(false)} 
        />
      </AnimatePresence>
    </>
  );
}