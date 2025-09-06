import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { DocumentTextIcon, ChartBarIcon, TableCellsIcon } from '@heroicons/react/24/outline';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import '../styles/cyberpunk-design-system.css';

const mockVulnerabilityData = [
  { severity: 'Critical', count: 5 },
  { severity: 'High', count: 12 },
  { severity: 'Medium', count: 8 },
  { severity: 'Low', count: 3 },
];

const mockSummary = 'Executive Summary: Your network has 28 vulnerabilities detected. Critical issues require immediate attention, focusing on web servers and databases. Overall risk level: High. Recommended actions: Patch SQL injection vectors and update authentication systems.';

export default function AdvancedReportingInterface() {
  const [reportElements, setReportElements] = useState([]);

  const addElement = (type) => {
    setReportElements([...reportElements, { id: Date.now(), type }]);
  };

  const generateSummary = () => {
    // In real implementation, this would call an AI service
    return mockSummary;
  };

  return (
    <div className="min-h-screen bg-space-gradient p-6">
      <motion.div 
        initial={{ opacity: 0, y: -50 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-12"
      >
        <h1 className="text-hero font-bold gradient-text mb-4">Advanced Reporting Center</h1>
        <p className="text-xl text-text-secondary">Generate executive summaries and build custom reports</p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Executive Summary Generator */}
        <motion.div className="glass-strong p-6 rounded-2xl">
          <div className="flex items-center mb-4">
            <DocumentTextIcon className="w-6 h-6 text-cyber-blue mr-2" />
            <h3 className="text-lg font-semibold gradient-text">Executive Summary Generator</h3>
          </div>
          <button 
            onClick={() => alert(generateSummary())}
            className="btn-primary w-full mb-4"
          >
            Generate Summary
          </button>
          <p className="text-text-secondary">Click to auto-generate AI-powered executive summary based on scan data.</p>
        </motion.div>

        {/* Interactive Report Builder */}
        <motion.div className="glass-strong p-6 rounded-2xl">
          <div className="flex items-center mb-4">
            <ChartBarIcon className="w-6 h-6 text-matrix-green mr-2" />
            <h3 className="text-lg font-semibold gradient-text">Interactive Report Builder</h3>
          </div>
          <div className="flex gap-4 mb-4">
            <button onClick={() => addElement('chart')} className="btn-secondary flex-1">Add Chart</button>
            <button onClick={() => addElement('table')} className="btn-secondary flex-1">Add Table</button>
          </div>
          <div className="min-h-64 border border-cyber-blue/20 rounded-lg p-4">
            {reportElements.map(element => (
              <motion.div 
                key={element.id} 
                className="mb-4"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
              >
                {element.type === 'chart' ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={mockVulnerabilityData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="severity" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="count" fill="var(--cyber-blue)" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="bg-bg-glass-subtle p-4 rounded">
                    <TableCellsIcon className="w-8 h-8 mx-auto text-neon-purple" />
                    <p className="text-center mt-2">Vulnerability Table Placeholder</p>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}