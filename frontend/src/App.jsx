import React from 'react';
import AppRoutes from './routes';
import { NotificationProvider, AlertsContainer } from './components/NotificationSystem';
import './styles/cyberpunk-design-system.css';

// Removed old navigation components - now using React Router

// Main App Component
function App() {
  return (
    <NotificationProvider>
      <div className="min-h-screen bg-space-gradient font-primary">
        <AlertsContainer />
        <AppRoutes />
      </div>
    </NotificationProvider>
  );
}

export default App;