import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Canvas, useFrame } from '@react-three/fiber';
import { Sphere, OrbitControls, Stars, Text } from '@react-three/drei';
import { useInView } from 'react-intersection-observer';
import { 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  CpuChipIcon,
  GlobeAltIcon,
  BoltIcon,
  EyeIcon
} from '@heroicons/react/24/outline';
import '../styles/cyberpunk-design-system.css';
import { useSpring, animated } from '@react-spring/web';
import NetworkTopologyViewer from './NetworkTopologyViewer';
import AIAgentMonitoringDashboard from './AIAgentMonitoringDashboard';

// 3D Rotating Earth Component
function RotatingEarth({ threats }) {
  const meshRef = useRef();
  
  useFrame((state, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.2;
    }
  });
  
  const springProps = useSpring({ 
    from: { scale: 0 },
    to: { scale: 1 },
    config: { duration: 1000, tension: 120 }
  });

  return (
    <group>
      <Sphere ref={meshRef} args={[2, 64, 64]}>
        <meshStandardMaterial 
          color="#0A1A2A" 
          wireframe={true}
          transparent={true}
          opacity={0.8}
        />
      </Sphere>
      
      {/* Threat indicators floating around Earth */}
      {threats.map((threat, index) => (
        <mesh 
          key={index}
          position={[
            Math.cos(index * 0.5) * 3,
            Math.sin(index * 0.3) * 2,
            Math.sin(index * 0.5) * 3
          ]}
        >
          <sphereGeometry args={[0.1, 8, 8]} />
          <meshBasicMaterial color={threat.severity === 'critical' ? '#FF073A' : '#FF8C00'} />
        </mesh>
      ))}
      
      <Stars radius={100} depth={50} count={5000} factor={4} saturation={0} fade speed={1} />
    </group>
  );
}

// Matrix-style Vulnerability Feed
function MatrixVulnerabilityFeed({ vulnerabilities }) {
  const [displayVulns, setDisplayVulns] = useState([]);
  
  useEffect(() => {
    const interval = setInterval(() => {
      if (vulnerabilities.length > 0) {
        const randomVuln = vulnerabilities[Math.floor(Math.random() * vulnerabilities.length)];
        setDisplayVulns(prev => {
          const newVulns = [randomVuln, ...prev.slice(0, 9)];
          return newVulns;
        });
      }
    }, 2000);
    
    return () => clearInterval(interval);
  }, [vulnerabilities]);
  
  return (
    <motion.div 
      className="matrix-rain h-80 overflow-hidden bg-bg-primary border border-matrix-green/30 rounded-xl p-4 glass-strong"
      initial={{ opacity: 0, backdropFilter: 'blur(0px)' }}
      animate={{ opacity: 1, backdropFilter: 'blur(10px)' }}
      transition={{ duration: 1, ease: 'easeInOut' }}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center">
          <BoltIcon className="w-4 h-4 text-matrix-green mr-2" />
          <h3 className="text-subheading font-semibold text-matrix-green">Live Feed</h3>
        </div>
        <span className="text-xs text-text-tertiary">{displayVulns.length} threats</span>
      </div>
      
      <div className="font-mono text-xs space-y-2 h-60 overflow-y-auto">
        <AnimatePresence>
          {displayVulns.map((vuln, index) => (
            <motion.div
              key={`${vuln.id}-${index}`}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1 - (index * 0.1), x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.5 }}
              className={`p-2 rounded bg-bg-glass-subtle border-l-2 ${
                vuln.severity === 'critical' ? 'border-critical-red text-critical-red' :
                vuln.severity === 'high' ? 'border-high-orange text-high-orange' :
                vuln.severity === 'medium' ? 'border-medium-yellow text-medium-yellow' :
                'border-low-blue text-low-blue'
              }`}
            >
              <div className="flex justify-between items-start">
                <span className="font-medium">{vuln.type}</span>
                <span className="text-text-tertiary text-xs">{new Date().toLocaleTimeString()}</span>
              </div>
              <div className="text-text-secondary mt-1">{vuln.target}</div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

// Threat Level Meter
function ThreatLevelMeter({ threatLevel, maxThreats }) {
  const percentage = (threatLevel / maxThreats) * 100;
  const getColor = () => {
    if (percentage >= 80) return 'critical-red';
    if (percentage >= 60) return 'high-orange';
    if (percentage >= 40) return 'medium-yellow';
    return 'low-blue';
  };
  
  return (
    <motion.div 
      className="glass-strong p-4 rounded-xl h-80"
      initial={{ filter: 'brightness(0.5)' }}
      animate={{ filter: 'brightness(1)' }}
      transition={{ duration: 1.5, ease: 'easeOut' }}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center">
          <ShieldCheckIcon className="w-4 h-4 text-cyber-blue mr-2" />
          <h3 className="text-subheading font-semibold gradient-text">Threat Level</h3>
        </div>
        <span className={`text-xs px-2 py-1 rounded-full bg-${getColor()}/20 text-${getColor()}`}>
          {percentage >= 80 ? 'CRITICAL' :
           percentage >= 60 ? 'HIGH' :
           percentage >= 40 ? 'ELEVATED' :
           'NORMAL'}
        </span>
      </div>
      
      <div className="flex flex-col items-center justify-center h-56">
        <div className="relative w-24 h-24 mb-4">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="35"
              stroke="rgba(255,255,255,0.1)"
              strokeWidth="6"
              fill="none"
            />
            <motion.circle
              cx="50"
              cy="50"
              r="35"
              stroke={`var(--${getColor()})`}
              strokeWidth="6"
              fill="none"
              strokeLinecap="round"
              strokeDasharray={`${2 * Math.PI * 35}`}
              initial={{ strokeDashoffset: 2 * Math.PI * 35 }}
              animate={{ strokeDashoffset: 2 * Math.PI * 35 * (1 - percentage / 100) }}
              transition={{ duration: 2, ease: "easeOut" }}
              className="glow-cyber"
            />
          </svg>
          
          <div className="absolute inset-0 flex items-center justify-center">
            <motion.div 
              className={`text-xl font-bold text-${getColor()}`}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 1, type: "spring" }}
            >
              {threatLevel}
            </motion.div>
          </div>
        </div>
        
        <div className="text-center">
          <div className="text-xs text-text-secondary mb-2">Active Threats</div>
          <div className="text-sm text-text-primary">{Math.round(percentage)}% of capacity</div>
        </div>
      </div>
    </motion.div>
  );
}


// Main Hero Dashboard Component
export default function HeroDashboard() {
  const [ref, inView] = useInView({ threshold: 0.1 });
  
  // Mock data - replace with real API calls
  const [dashboardData, setDashboardData] = useState({
    threats: [
      { id: 1, severity: 'critical', location: 'Web Server' },
      { id: 2, severity: 'high', location: 'Database' },
      { id: 3, severity: 'medium', location: 'API Gateway' }
    ],
    vulnerabilities: [
      { id: 1, type: 'SQL Injection', target: '192.168.1.100', severity: 'critical' },
      { id: 2, type: 'XSS', target: 'app.example.com', severity: 'high' },
      { id: 3, type: 'CSRF', target: 'api.example.com', severity: 'medium' },
      { id: 4, type: 'Path Traversal', target: '10.0.0.50', severity: 'high' }
    ],
    agents: [
      { 
        id: 1, 
        name: 'Reconnaissance Agent', 
        status: 'active', 
        currentTask: 'Port scanning 192.168.1.0/24', 
        progress: 75,
        technique: 'Nmap SYN Scan'
      },
      { 
        id: 2, 
        name: 'Vulnerability Scanner', 
        status: 'scanning', 
        currentTask: 'Testing SQL injection vectors', 
        progress: 45,
        technique: 'SQLMap'
      },
      { 
        id: 3, 
        name: 'Web Application Tester', 
        status: 'active', 
        currentTask: 'Analyzing authentication bypass', 
        progress: 90,
        technique: 'Custom Payloads'
      }
    ],
    networkData: {
      nodes: [
        { id: 1, name: 'Web Server', vulnerable: true },
        { id: 2, name: 'Database', vulnerable: false },
        { id: 3, name: 'API Gateway', vulnerable: true },
        { id: 4, name: 'Load Balancer', vulnerable: false },
        { id: 5, name: 'Cache Server', vulnerable: false },
        { id: 6, name: 'File Server', vulnerable: true }
      ]
    }
  });
  
  return (
    <div ref={ref} className="min-h-screen bg-space-gradient p-6">
      {/* Compact Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={inView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.6 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-display font-bold gradient-text mb-2">
              Command Center
            </h1>
            <p className="text-body text-text-secondary">
              Real-time cybersecurity monitoring and threat analysis
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="btn-cyber px-4 py-2 text-sm"
            >
              Start Scan
            </motion.button>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="btn-ghost px-4 py-2 text-sm"
            >
              View Reports
            </motion.button>
          </div>
        </div>
      </motion.div>
      
      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6 mb-6 grid-responsive">
        {/* 3D Earth Visualization */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={inView ? { opacity: 1, scale: 1 } : {}}
          transition={{ duration: 0.8, delay: 0.2 }}
          className="lg:col-span-2 glass p-4 rounded-xl h-80"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center">
              <GlobeAltIcon className="w-5 h-5 text-cyber-blue mr-2" />
              <h3 className="text-heading font-semibold gradient-text">Global Threats</h3>
            </div>
            <span className="text-sm text-text-tertiary">{dashboardData.threats.length} active</span>
          </div>
          
          <div className="h-64 canvas-container">
            <Canvas camera={{ position: [0, 0, 8] }}>
              <ambientLight intensity={0.5} />
              <pointLight position={[10, 10, 10]} />
              <RotatingEarth threats={dashboardData.threats} />
              <OrbitControls enableZoom={false} autoRotate autoRotateSpeed={0.5} />
            </Canvas>
          </div>
          
          {/* Mobile fallback */}
          <div className="h-64 md:hidden flex items-center justify-center bg-bg-glass-subtle rounded-lg">
            <div className="text-center">
              <GlobeAltIcon className="w-16 h-16 text-cyber-blue mx-auto mb-4" />
              <div className="text-heading font-semibold text-text-primary mb-2">Global Threats</div>
              <div className="text-sm text-text-secondary">{dashboardData.threats.length} active threats detected</div>
            </div>
          </div>
        </motion.div>
        
        {/* Threat Level Meter */}
        <motion.div
          initial={{ opacity: 0, x: 50 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="lg:col-span-1"
        >
          <ThreatLevelMeter threatLevel={dashboardData.threats.length} maxThreats={10} />
        </motion.div>
        
        {/* Quick Stats */}
        <motion.div
          initial={{ opacity: 0, x: 50 }}
          animate={inView ? { opacity: 1, x: 0 } : {}}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="lg:col-span-1 space-y-3"
        >
          {[
            { label: 'Active Scans', value: '3', icon: EyeIcon, color: 'cyber-blue' },
            { label: 'Vulnerabilities', value: '12', icon: ExclamationTriangleIcon, color: 'critical-red' },
            { label: 'Systems', value: '47', icon: ShieldCheckIcon, color: 'matrix-green' },
            { label: 'AI Agents', value: '3', icon: CpuChipIcon, color: 'neon-purple' }
          ].map((stat, index) => (
            <div key={index} className="glass p-3 rounded-lg flex items-center space-x-3">
              <stat.icon className={`w-6 h-6 text-${stat.color}`} />
              <div>
                <div className={`text-lg font-bold text-${stat.color}`}>{stat.value}</div>
                <div className="text-xs text-text-secondary">{stat.label}</div>
              </div>
            </div>
          ))}
        </motion.div>
      </div>
      
      {/* Secondary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6 grid-responsive">
        {/* Matrix Vulnerability Feed */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="lg:col-span-1"
        >
          <MatrixVulnerabilityFeed vulnerabilities={dashboardData.vulnerabilities} />
        </motion.div>
        
        {/* AI Agent Monitoring Dashboard */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 1.0 }}
          className="lg:col-span-1"
        >
          <AIAgentMonitoringDashboard agents={dashboardData.agents} />
        </motion.div>
        
        {/* Network Topology */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 1.2 }}
          className="lg:col-span-1"
        >
          <NetworkTopologyViewer networkData={dashboardData.networkData} />
        </motion.div>
      </div>
    </div>
  );
}