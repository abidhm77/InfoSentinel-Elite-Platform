import React, { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowUpIcon,
  ArrowDownIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ChartBarIcon,
  ClockIcon,
  UserGroupIcon,
  ServerIcon,
  BugAntIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import '../styles/cyberpunk-design-system.css';
import axios from 'axios';

// KPI Card Component
function KPICard({ title, value, change, changeType, icon: Icon, color = 'cyber-blue', trend = [] }) {
  const isPositive = changeType === 'positive';
  const isNegative = changeType === 'negative';
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-strong p-6 rounded-xl hover:scale-105 transition-transform duration-300"
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-lg bg-${color}/10`}>
          <Icon className={`w-6 h-6 text-${color}`} />
        </div>
        {trend.length > 0 && (
          <div className="w-16 h-8">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trend}>
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke={`var(--${color})`}
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
      
      <div className="space-y-2">
        <h3 className="text-sm font-medium text-text-secondary">{title}</h3>
        <div className="flex items-end justify-between">
          <span className="text-2xl font-bold text-text-primary">{value}</span>
          {change && (
            <div className={`flex items-center space-x-1 text-sm ${
              isPositive ? 'text-success-green' :
              isNegative ? 'text-critical-red' :
              'text-text-secondary'
            }`}>
              {isPositive && <ArrowUpIcon className="w-4 h-4" />}
              {isNegative && <ArrowDownIcon className="w-4 h-4" />}
              <span>{change}</span>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// Executive Summary Component
function ExecutiveSummary({ data }) {
  const insights = [
    {
      type: 'critical',
      title: 'Critical Security Alert',
      description: '3 critical vulnerabilities detected in the last 24 hours requiring immediate attention.',
      action: 'Review Critical Issues',
      priority: 'high'
    },
    {
      type: 'improvement',
      title: 'Security Posture Improved',
      description: 'Overall security score increased by 15% this month through proactive remediation.',
      action: 'View Detailed Report',
      priority: 'medium'
    },
    {
      type: 'compliance',
      title: 'Compliance Status',
      description: '98% compliance achieved across all frameworks. 2 minor issues pending resolution.',
      action: 'View Compliance Dashboard',
      priority: 'low'
    }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="glass-strong p-6 rounded-xl"
    >
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-heading font-semibold gradient-text">Executive Summary</h2>
        <span className="text-sm text-text-tertiary">Last updated: {new Date().toLocaleString()}</span>
      </div>
      
      <div className="space-y-4">
        {insights.map((insight, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className={`p-4 rounded-lg border-l-4 ${
              insight.type === 'critical' ? 'border-critical-red bg-critical-red/5' :
              insight.type === 'improvement' ? 'border-success-green bg-success-green/5' :
              'border-cyber-blue bg-cyber-blue/5'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h3 className={`font-medium text-sm mb-2 ${
                  insight.type === 'critical' ? 'text-critical-red' :
                  insight.type === 'improvement' ? 'text-success-green' :
                  'text-cyber-blue'
                }`}>
                  {insight.title}
                </h3>
                <p className="text-text-secondary text-sm mb-3">{insight.description}</p>
                <button className={`text-xs font-medium hover:underline ${
                  insight.type === 'critical' ? 'text-critical-red' :
                  insight.type === 'improvement' ? 'text-success-green' :
                  'text-cyber-blue'
                }`}>
                  {insight.action} →
                </button>
              </div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                insight.priority === 'high' ? 'bg-critical-red/20 text-critical-red' :
                insight.priority === 'medium' ? 'bg-high-orange/20 text-high-orange' :
                'bg-cyber-blue/20 text-cyber-blue'
              }`}>
                {insight.priority.toUpperCase()}
              </span>
            </div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}

// Threat Trends Chart
function ThreatTrendsChart({ data }) {
  const chartData = [
    { name: 'Jan', critical: 4, high: 12, medium: 23, low: 8 },
    { name: 'Feb', critical: 2, high: 15, medium: 18, low: 12 },
    { name: 'Mar', critical: 6, high: 8, medium: 25, low: 15 },
    { name: 'Apr', critical: 3, high: 18, medium: 20, low: 10 },
    { name: 'May', critical: 1, high: 10, medium: 28, low: 18 },
    { name: 'Jun', critical: 5, high: 14, medium: 22, low: 14 }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-strong p-6 rounded-xl"
    >
      <h3 className="text-heading font-semibold gradient-text mb-6">Threat Trends (6 Months)</h3>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
            <XAxis dataKey="name" stroke="#8E8E93" />
            <YAxis stroke="#8E8E93" />
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(28, 28, 30, 0.95)',
                border: '1px solid rgba(0, 245, 255, 0.3)',
                borderRadius: '8px',
                color: '#FFFFFF'
              }}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#FF073A"
              fill="#FF073A"
              fillOpacity={0.6}
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#FF8C00"
              fill="#FF8C00"
              fillOpacity={0.6}
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#FFD700"
              fill="#FFD700"
              fillOpacity={0.6}
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#4A90E2"
              fill="#4A90E2"
              fillOpacity={0.6}
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

// Security Score Gauge
function SecurityScoreGauge({ score = 85 }) {
  const getScoreColor = (score) => {
    if (score >= 90) return 'success-green';
    if (score >= 70) return 'cyber-blue';
    if (score >= 50) return 'medium-yellow';
    return 'critical-red';
  };

  const getScoreLabel = (score) => {
    if (score >= 90) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDasharray = circumference;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-strong p-6 rounded-xl text-center"
    >
      <h3 className="text-heading font-semibold gradient-text mb-6">Security Score</h3>
      
      <div className="relative w-32 h-32 mx-auto mb-4">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          <circle
            cx="50"
            cy="50"
            r="45"
            stroke="rgba(255,255,255,0.1)"
            strokeWidth="8"
            fill="none"
          />
          <motion.circle
            cx="50"
            cy="50"
            r="45"
            stroke={`var(--${getScoreColor(score)})`}
            strokeWidth="8"
            fill="none"
            strokeLinecap="round"
            strokeDasharray={strokeDasharray}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 2, ease: "easeOut" }}
            className="glow-cyber"
          />
        </svg>
        
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <motion.div 
              className={`text-3xl font-bold text-${getScoreColor(score)}`}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 1, type: "spring" }}
            >
              {score}
            </motion.div>
            <div className="text-xs text-text-secondary">/ 100</div>
          </div>
        </div>
      </div>
      
      <div className={`text-sm font-medium text-${getScoreColor(score)} mb-2`}>
        {getScoreLabel(score)}
      </div>
      <div className="text-xs text-text-secondary">
        Based on vulnerability assessment
      </div>
    </motion.div>
  );
}

// Vulnerability Distribution Chart
function VulnerabilityDistribution() {
  const data = [
    { name: 'Web Application', value: 35, color: '#FF073A' },
    { name: 'Network', value: 25, color: '#FF8C00' },
    { name: 'System', value: 20, color: '#FFD700' },
    { name: 'Database', value: 15, color: '#4A90E2' },
    { name: 'Other', value: 5, color: '#9D00FF' }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-strong p-6 rounded-xl"
    >
      <h3 className="text-heading font-semibold gradient-text mb-6">Vulnerability Distribution</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={40}
              outerRadius={80}
              paddingAngle={5}
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(28, 28, 30, 0.95)',
                border: '1px solid rgba(0, 245, 255, 0.3)',
                borderRadius: '8px',
                color: '#FFFFFF'
              }}
            />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

// Recent Activity Feed
function RecentActivityFeed() {
  const activities = [
    {
      id: 1,
      type: 'scan',
      title: 'Network scan completed',
      description: '192.168.1.0/24 - 15 vulnerabilities found',
      time: '5 minutes ago',
      severity: 'high'
    },
    {
      id: 2,
      type: 'vulnerability',
      title: 'Critical vulnerability detected',
      description: 'SQL injection in user authentication',
      time: '12 minutes ago',
      severity: 'critical'
    },
    {
      id: 3,
      type: 'report',
      title: 'Monthly report generated',
      description: 'Executive security assessment completed',
      time: '1 hour ago',
      severity: 'info'
    },
    {
      id: 4,
      type: 'remediation',
      title: 'Vulnerability remediated',
      description: 'XSS vulnerability in contact form fixed',
      time: '2 hours ago',
      severity: 'success'
    }
  ];

  const getActivityIcon = (type) => {
    switch (type) {
      case 'scan': return ServerIcon;
      case 'vulnerability': return BugAntIcon;
      case 'report': return DocumentTextIcon;
      case 'remediation': return ShieldCheckIcon;
      default: return ClockIcon;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'critical-red';
      case 'high': return 'high-orange';
      case 'success': return 'success-green';
      default: return 'cyber-blue';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      className="glass-strong p-6 rounded-xl"
    >
      <h3 className="text-heading font-semibold gradient-text mb-6">Recent Activity</h3>
      <div className="space-y-4 max-h-96 overflow-y-auto">
        {activities.map((activity, index) => {
          const Icon = getActivityIcon(activity.type);
          const colorClass = getSeverityColor(activity.severity);
          
          return (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-start space-x-3 p-3 bg-bg-glass-subtle rounded-lg hover:bg-bg-glass transition-colors duration-200"
            >
              <div className={`p-2 rounded-lg bg-${colorClass}/10`}>
                <Icon className={`w-4 h-4 text-${colorClass}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <h4 className="text-sm font-medium text-text-primary truncate">
                    {activity.title}
                  </h4>
                  <span className="text-xs text-text-tertiary">
                    {activity.time}
                  </span>
                </div>
                <p className="text-xs text-text-secondary">{activity.description}</p>
              </div>
            </motion.div>
          );
        })}
      </div>
    </motion.div>
  );
}

// Main Enterprise Dashboard Component
export default function EnterpriseDashboard() {
  const [timeRange, setTimeRange] = useState('7d');
  
  // Mock KPI data
  const kpiData = [
    {
      title: 'Total Vulnerabilities',
      value: '247',
      change: '+12%',
      changeType: 'negative',
      icon: BugAntIcon,
      color: 'critical-red',
      trend: [{ value: 235 }, { value: 240 }, { value: 245 }, { value: 247 }]
    },
    {
      title: 'Critical Issues',
      value: '8',
      change: '-25%',
      changeType: 'positive',
      icon: ExclamationTriangleIcon,
      color: 'high-orange',
      trend: [{ value: 12 }, { value: 10 }, { value: 9 }, { value: 8 }]
    },
    {
      title: 'Systems Scanned',
      value: '156',
      change: '+8%',
      changeType: 'positive',
      icon: ServerIcon,
      color: 'cyber-blue',
      trend: [{ value: 144 }, { value: 148 }, { value: 152 }, { value: 156 }]
    },
    {
      title: 'Compliance Score',
      value: '98%',
      change: '+2%',
      changeType: 'positive',
      icon: ShieldCheckIcon,
      color: 'success-green',
      trend: [{ value: 96 }, { value: 97 }, { value: 97 }, { value: 98 }]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-display font-bold gradient-text mb-2">
            Security Dashboard
          </h1>
          <p className="text-body text-text-secondary">
            Comprehensive overview of your security posture and threat landscape
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-bg-glass border border-cyber-blue/30 rounded-lg px-4 py-2 text-sm text-text-primary focus:outline-none focus:border-cyber-blue"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {kpiData.map((kpi, index) => (
          <KPICard key={index} {...kpi} />
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Executive Summary */}
        <div className="lg:col-span-2">
          <ExecutiveSummary />
        </div>
        
        {/* Security Score */}
        <div>
          <SecurityScoreGauge score={85} />
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatTrendsChart />
        <VulnerabilityDistribution />
      </div>

      {/* Recent Activity */}
      <RecentActivityFeed />
    </div>
  );
}

function GRCBoardDashboard({ tenantIds }) {
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const response = await axios.post('/api/v1/msp/reports/grc-board-report', { tenant_ids: tenantIds });
        setReportData(response.data.report);
      } catch (error) {
        console.error('Error fetching GRC report:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [tenantIds]);

  if (loading) return <div>Loading GRC Board Report...</div>;

  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-strong p-6 rounded-xl">
      <h3 className="text-heading font-semibold gradient-text mb-6">GRC Board Dashboard</h3>
      <div className="space-y-4">
        <div>
          <h4>Risk Assessment</h4>
          <pre>{JSON.stringify(reportData.risk_assessment, null, 2)}</pre>
        </div>
        <div>
          <h4>Compliance Summary</h4>
          <pre>{JSON.stringify(reportData.compliance_summary, null, 2)}</pre>
        </div>
        <p>{reportData.executive_overview}</p>
      </div>
    </motion.div>
  );
}