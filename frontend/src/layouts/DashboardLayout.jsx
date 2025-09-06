import React, { useState } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { 
  FiHome, 
  FiSearch, 
  FiFileText, 
  FiSettings, 
  FiLogOut, 
  FiMenu, 
  FiX,
  FiBell,
  FiBarChart
} from 'react-icons/fi';

const DashboardLayout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: <FiHome className="w-5 h-5" /> },
    { path: '/visualizations', label: 'Visualizations', icon: <FiBarChart className="w-5 h-5" /> },
    { path: '/scans', label: 'Scans', icon: <FiSearch className="w-5 h-5" /> },
    { path: '/reports', label: 'Reports', icon: <FiFileText className="w-5 h-5" /> },
    { path: '/settings', label: 'Settings', icon: <FiSettings className="w-5 h-5" /> },
  ];

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-gray-900">
      {/* Sidebar */}
      <aside 
        className={`fixed inset-y-0 z-10 flex flex-col flex-shrink-0 w-64 max-h-screen overflow-hidden transition-all transform bg-white dark:bg-gray-800 border-r dark:border-gray-700 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        {/* Logo */}
        <div className="flex items-center justify-between flex-shrink-0 p-4">
          <Link to="/" className="flex items-center space-x-2">
            <span className="text-xl font-semibold tracking-wider text-gray-800 dark:text-white">
              SecureScout
            </span>
          </Link>
          <button
            onClick={() => setSidebarOpen(false)}
            className="p-1 rounded-md md:hidden focus:outline-none focus:ring"
          >
            <FiX className="w-6 h-6 text-gray-600 dark:text-gray-300" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-auto">
          <ul className="p-2 space-y-1">
            {navItems.map((item) => (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`flex items-center px-4 py-3 transition-colors rounded-md ${
                    location.pathname === item.path
                      ? 'bg-blue-100 dark:bg-blue-800 text-blue-700 dark:text-blue-100'
                      : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
                >
                  {item.icon}
                  <span className="ml-3">{item.label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        {/* Enterprise User Profile */}
        <div style={{padding: '1rem', borderTop: '1px solid var(--border-color)'}}>
          <div className="enterprise-card" style={{padding: '1rem'}}>
            <div style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
              <div style={{
                width: '2.5rem',
                height: '2.5rem',
                background: 'linear-gradient(135deg, var(--primary-color), var(--primary-light))',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <span style={{color: 'white', fontSize: '0.875rem', fontWeight: '600'}}>
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </span>
              </div>
              <div style={{flex: 1}}>
                <p style={{margin: 0, fontSize: '0.875rem', fontWeight: '600', color: 'var(--text-primary)'}}>
                  {user?.username || 'User'}
                </p>
                <p style={{margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)'}}>
                  {user?.role || 'User'}
                </p>
              </div>
              <button
                onClick={handleLogout}
                className="enterprise-btn"
                style={{
                  padding: '0.5rem',
                  background: 'transparent',
                  color: 'var(--text-secondary)',
                  border: '1px solid var(--border-color)'
                }}
              >
                <FiLogOut style={{width: '1rem', height: '1rem'}} />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Enterprise Main Content */}
      <div style={{display: 'flex', flexDirection: 'column', flex: 1}} className="md:pl-64">
        {/* Enterprise Header */}
        <header 
          style={{
            zIndex: 10,
            padding: '1rem',
            background: 'rgba(255, 255, 255, 0.95)',
            backdropFilter: 'blur(10px)',
            borderBottom: '1px solid var(--border-color)',
            boxShadow: 'var(--shadow-sm)'
          }}
        >
          <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between'}}>
            <button
              onClick={() => setSidebarOpen(true)}
              className="enterprise-btn md:hidden"
              style={{
                padding: '0.5rem',
                background: 'transparent',
                border: '1px solid var(--border-color)'
              }}
            >
              <FiMenu style={{width: '1.25rem', height: '1.25rem'}} />
            </button>

            <div style={{display: 'flex', alignItems: 'center', gap: '1rem'}}>
              <button 
                className="enterprise-btn"
                style={{
                  padding: '0.5rem',
                  background: 'transparent',
                  border: '1px solid var(--border-color)'
                }}
              >
                <FiBell style={{width: '1.25rem', height: '1.25rem'}} />
              </button>
            </div>
          </div>
        </header>

        {/* Enterprise Page Content */}
        <main style={{flex: 1, overflow: 'auto', padding: '1rem 1.5rem 2rem'}}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;