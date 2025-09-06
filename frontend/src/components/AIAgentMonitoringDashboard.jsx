import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { CpuChipIcon, UserCircleIcon } from '@heroicons/react/24/outline';
import '../styles/cyberpunk-design-system.css';

function AgentAvatar({ status }) {
  return (
    <div className={`relative w-16 h-16 rounded-full overflow-hidden border-2 ${status === 'active' ? 'border-matrix-green glow-matrix' : 'border-cyber-blue glow-cyber'}`}>
      <UserCircleIcon className="w-full h-full text-text-secondary" />
      <div className={`absolute inset-0 bg-${status === 'active' ? 'matrix-green' : 'cyber-blue'} opacity-20`} />
    </div>
  );
}

export default function AIAgentMonitoringDashboard({ agents }) {
  const [liveAgents, setLiveAgents] = useState(agents);

  useEffect(() => {
    const interval = setInterval(() => {
      setLiveAgents(prev => prev.map(agent => ({
        ...agent,
        progress: Math.min(100, agent.progress + Math.random() * 5),
        status: Math.random() > 0.5 ? 'active' : 'scanning'
      })));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-strong p-6 rounded-2xl">
      <div className="flex items-center mb-6">
        <CpuChipIcon className="w-6 h-6 text-cyber-blue mr-2" />
        <h3 className="text-lg font-semibold gradient-text">AI Agents Monitor</h3>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {liveAgents.map((agent) => (
          <motion.div
            key={agent.id}
            className="glass p-4 rounded-xl"
            whileHover={{ scale: 1.05 }}
            transition={{ duration: 0.3 }}
          >
            <div className="flex items-center mb-4">
              <AgentAvatar status={agent.status} />
              <div className="ml-4">
                <h4 className="font-medium text-text-primary">{agent.name}</h4>
                <p className="text-sm text-text-secondary">{agent.technique}</p>
              </div>
            </div>
            <div className="mb-2 text-sm text-text-secondary">{agent.currentTask}</div>
            <div className="relative h-2 bg-bg-secondary rounded-full overflow-hidden">
              <motion.div
                className="absolute inset-0 bg-gradient-to-r from-cyber-blue to-matrix-green"
                initial={{ width: '0%' }}
                animate={{ width: `${agent.progress}%` }}
                transition={{ duration: 1 }}
              />
            </div>
            <div className="text-right text-sm text-cyber-blue mt-1">{Math.round(agent.progress)}%</div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}