import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import DashboardLayout from './layouts/DashboardLayout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanDetails from './pages/ScanDetails';
import VisualizationDashboard from './pages/VisualizationDashboard';
import AdminDashboard from './components/AdminDashboard';

// Auth pages would be implemented in a real application
const Login = () => <div className="p-8 text-center">Login Page (Mock)</div>;
const Register = () => <div className="p-8 text-center">Register Page (Mock)</div>;

const AppRoutes = () => {
  // In a real app, this would check for authentication
  const isAuthenticated = true;

  return (
    <Routes>
      {/* Auth Routes */}
      <Route path="/login" element={!isAuthenticated ? <Login /> : <Navigate to="/dashboard" />} />
      <Route path="/register" element={!isAuthenticated ? <Register /> : <Navigate to="/dashboard" />} />
      
      {/* Protected Routes */}
      <Route path="/" element={isAuthenticated ? <DashboardLayout /> : <Navigate to="/login" />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="visualizations" element={<VisualizationDashboard />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="scans/:scanId" element={<ScanDetails />} />
        <Route path="admin" element={<AdminDashboard />} />
      </Route>
      
      {/* Fallback route */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
};

export default AppRoutes;