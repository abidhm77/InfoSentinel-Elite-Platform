import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import NetworkTopologyVisualization from '../components/visualizations/NetworkTopologyVisualization';
import AttackPathVisualization from '../components/visualizations/AttackPathVisualization';
import RiskHeatMapVisualization from '../components/visualizations/RiskHeatMapVisualization';
import { Network, Shield, BarChart3, AlertTriangle, Target, Activity } from 'lucide-react';

const VisualizationDashboard = () => {
  const [activeTab, setActiveTab] = useState('network');
  const [networkData, setNetworkData] = useState(null);
  const [attackPaths, setAttackPaths] = useState([]);
  const [riskData, setRiskData] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);

  // Sample data for demonstration
  useEffect(() => {
    // Simulate loading data
    setTimeout(() => {
      // Sample network topology data
      setNetworkData({
        nodes: [
          {
            id: 'firewall-1',
            hostname: 'fw-main',
            ip: '192.168.1.1',
            type: 'firewall',
            os: 'pfSense',
            services: [
              { name: 'ssh', port: 22 },
              { name: 'https', port: 443 }
            ]
          },
          {
            id: 'web-server-1',
            hostname: 'web-prod',
            ip: '192.168.1.10',
            type: 'server',
            os: 'Ubuntu 20.04',
            services: [
              { name: 'http', port: 80 },
              { name: 'https', port: 443 },
              { name: 'ssh', port: 22 }
            ]
          },
          {
            id: 'db-server-1',
            hostname: 'db-prod',
            ip: '192.168.1.20',
            type: 'database',
            os: 'CentOS 8',
            services: [
              { name: 'mysql', port: 3306 },
              { name: 'ssh', port: 22 }
            ]
          },
          {
            id: 'workstation-1',
            hostname: 'ws-admin',
            ip: '192.168.1.100',
            type: 'host',
            os: 'Windows 10',
            services: [
              { name: 'rdp', port: 3389 },
              { name: 'smb', port: 445 }
            ]
          },
          {
            id: 'router-1',
            hostname: 'rtr-core',
            ip: '192.168.1.254',
            type: 'router',
            os: 'Cisco IOS',
            services: [
              { name: 'ssh', port: 22 },
              { name: 'snmp', port: 161 }
            ]
          }
        ],
        links: [
          {
            source: 'router-1',
            target: 'firewall-1',
            type: 'direct',
            protocol: 'ethernet'
          },
          {
            source: 'firewall-1',
            target: 'web-server-1',
            type: 'secure',
            protocol: 'tcp'
          },
          {
            source: 'firewall-1',
            target: 'db-server-1',
            type: 'secure',
            protocol: 'tcp'
          },
          {
            source: 'firewall-1',
            target: 'workstation-1',
            type: 'direct',
            protocol: 'tcp'
          },
          {
            source: 'web-server-1',
            target: 'db-server-1',
            type: 'direct',
            protocol: 'tcp'
          }
        ]
      });

      // Sample vulnerabilities
      setVulnerabilities([
        {
          _id: 'vuln-1',
          host: '192.168.1.10',
          title: 'Apache HTTP Server Vulnerability',
          severity: 'high',
          cvss_score: 7.5,
          description: 'Remote code execution vulnerability in Apache HTTP Server'
        },
        {
          _id: 'vuln-2',
          host: '192.168.1.20',
          title: 'MySQL Privilege Escalation',
          severity: 'critical',
          cvss_score: 9.1,
          description: 'Local privilege escalation in MySQL server'
        },
        {
          _id: 'vuln-3',
          host: '192.168.1.100',
          title: 'Windows SMB Vulnerability',
          severity: 'medium',
          cvss_score: 5.4,
          description: 'Information disclosure via SMB protocol'
        }
      ]);

      // Sample attack paths
      setAttackPaths([
        {
          id: 'attack-path-1',
          name: 'Web Application Attack Chain',
          description: 'Multi-stage attack targeting web infrastructure',
          riskLevel: 'high',
          overallRisk: 8.5,
          steps: [
            {
              title: 'Initial Access',
              technique: 'initial-access',
              vector: 'network',
              riskScore: 7,
              description: 'Exploit web application vulnerability to gain initial foothold',
              mitigations: [
                'Update Apache HTTP Server',
                'Implement Web Application Firewall',
                'Regular security scanning'
              ],
              affectedAssets: [
                { name: 'web-prod', ip: '192.168.1.10' }
              ]
            },
            {
              title: 'Privilege Escalation',
              technique: 'privilege-escalation',
              vector: 'host',
              riskScore: 8,
              description: 'Escalate privileges using local vulnerability',
              mitigations: [
                'Apply security patches',
                'Implement least privilege principle',
                'Monitor privilege escalation attempts'
              ],
              affectedAssets: [
                { name: 'web-prod', ip: '192.168.1.10' }
              ]
            },
            {
              title: 'Lateral Movement',
              technique: 'lateral-movement',
              vector: 'network',
              riskScore: 9,
              description: 'Move laterally to database server',
              mitigations: [
                'Network segmentation',
                'Monitor east-west traffic',
                'Implement zero trust architecture'
              ],
              affectedAssets: [
                { name: 'db-prod', ip: '192.168.1.20' }
              ]
            },
            {
              title: 'Data Exfiltration',
              technique: 'exfiltration',
              vector: 'application',
              riskScore: 10,
              description: 'Extract sensitive data from database',
              mitigations: [
                'Database encryption',
                'Data loss prevention',
                'Access logging and monitoring'
              ],
              affectedAssets: [
                { name: 'db-prod', ip: '192.168.1.20' }
              ]
            }
          ]
        },
        {
          id: 'attack-path-2',
          name: 'Internal Threat Scenario',
          description: 'Insider threat leveraging administrative access',
          riskLevel: 'critical',
          overallRisk: 9.2,
          steps: [
            {
              title: 'Credential Access',
              technique: 'credential-access',
              vector: 'social',
              riskScore: 6,
              description: 'Obtain administrative credentials through social engineering',
              mitigations: [
                'Security awareness training',
                'Multi-factor authentication',
                'Privileged access management'
              ],
              affectedAssets: [
                { name: 'ws-admin', ip: '192.168.1.100' }
              ]
            },
            {
              title: 'System Access',
              technique: 'initial-access',
              vector: 'host',
              riskScore: 8,
              description: 'Access administrative workstation',
              mitigations: [
                'Endpoint detection and response',
                'Session monitoring',
                'Just-in-time access'
              ],
              affectedAssets: [
                { name: 'ws-admin', ip: '192.168.1.100' }
              ]
            },
            {
              title: 'Infrastructure Control',
              technique: 'impact',
              vector: 'network',
              riskScore: 10,
              description: 'Gain control over network infrastructure',
              mitigations: [
                'Network access control',
                'Infrastructure monitoring',
                'Change management controls'
              ],
              affectedAssets: [
                { name: 'rtr-core', ip: '192.168.1.254' },
                { name: 'fw-main', ip: '192.168.1.1' }
              ]
            }
          ]
        }
      ]);

      // Sample risk data
      setRiskData([
        {
          asset: '192.168.1.10',
          hostname: 'web-prod',
          vulnerability_count: 3,
          risk_score: 7.5,
          compliance_score: 65,
          severity: 'high',
          created_at: '2024-01-15T10:00:00Z',
          service: 'http',
          port: 80,
          type: 'web_vulnerability'
        },
        {
          asset: '192.168.1.20',
          hostname: 'db-prod',
          vulnerability_count: 2,
          risk_score: 9.1,
          compliance_score: 45,
          severity: 'critical',
          created_at: '2024-01-15T11:00:00Z',
          service: 'mysql',
          port: 3306,
          type: 'database_vulnerability'
        },
        {
          asset: '192.168.1.100',
          hostname: 'ws-admin',
          vulnerability_count: 1,
          risk_score: 5.4,
          compliance_score: 80,
          severity: 'medium',
          created_at: '2024-01-15T12:00:00Z',
          service: 'smb',
          port: 445,
          type: 'network_vulnerability'
        },
        {
          asset: '192.168.1.1',
          hostname: 'fw-main',
          vulnerability_count: 0,
          risk_score: 2.1,
          compliance_score: 95,
          severity: 'low',
          created_at: '2024-01-15T13:00:00Z',
          service: 'ssh',
          port: 22,
          type: 'configuration_issue'
        },
        {
          asset: '192.168.1.254',
          hostname: 'rtr-core',
          vulnerability_count: 1,
          risk_score: 4.2,
          compliance_score: 70,
          severity: 'medium',
          created_at: '2024-01-15T14:00:00Z',
          service: 'snmp',
          port: 161,
          type: 'protocol_vulnerability'
        }
      ]);

      setLoading(false);
    }, 1000);
  }, []);

  const handleNodeClick = (node) => {
    console.log('Node clicked:', node);
    // You can add custom logic here, like showing detailed information
  };

  const handlePathSelect = (path) => {
    console.log('Attack path selected:', path);
    // You can add custom logic here
  };

  const handleCellClick = (cell) => {
    console.log('Risk cell clicked:', cell);
    // You can add custom logic here
  };

  if (loading) {
    return (
      <div className="enterprise-loading">
        <div className="enterprise-spinner"></div>
        <h3 style={{color: 'var(--text-primary)', marginTop: '1rem'}}>Loading Security Visualizations...</h3>
        <p style={{color: 'var(--text-secondary)'}}>Preparing interactive dashboards and analytics</p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in" style={{padding: '2rem', minHeight: '100vh'}}>
      {/* Enterprise Header */}
      <div className="enterprise-card" style={{marginBottom: '2rem'}}>
        <div className="enterprise-card-header">
          <div style={{display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem'}}>
            <div>
              <h1 style={{margin: 0, fontSize: '2rem', fontWeight: '700'}}>Security Visualization Center</h1>
              <p style={{margin: '0.5rem 0 0 0', opacity: 0.9}}>
                Advanced interactive security analytics and threat intelligence
              </p>
            </div>
            
            <div style={{display: 'flex', gap: '1rem', flexWrap: 'wrap'}}>
              <div className="enterprise-badge enterprise-badge-info" style={{display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                <Network style={{width: '1rem', height: '1rem'}} />
                {networkData?.nodes?.length || 0} Assets
              </div>
              <div className="enterprise-badge enterprise-badge-error" style={{display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                <AlertTriangle style={{width: '1rem', height: '1rem'}} />
                {vulnerabilities.length} Vulnerabilities
              </div>
              <div className="enterprise-badge enterprise-badge-warning" style={{display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                <Target style={{width: '1rem', height: '1rem'}} />
                {attackPaths.length} Attack Paths
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Enterprise Statistics */}
      <div className="enterprise-stats">
        <div className="enterprise-stat-card animate-slide-up">
          <div className="enterprise-stat-value">{networkData?.nodes?.length || 0}</div>
          <div className="enterprise-stat-label">Network Assets</div>
          <Network style={{width: '2rem', height: '2rem', color: 'var(--primary-color)', margin: '0.5rem auto 0'}} />
        </div>
        
        <div className="enterprise-stat-card animate-slide-up" style={{animationDelay: '0.1s'}}>
          <div className="enterprise-stat-value" style={{color: 'var(--error-color)'}}>{vulnerabilities.length}</div>
          <div className="enterprise-stat-label">Active Vulnerabilities</div>
          <AlertTriangle style={{width: '2rem', height: '2rem', color: 'var(--error-color)', margin: '0.5rem auto 0'}} />
        </div>
        
        <div className="enterprise-stat-card animate-slide-up" style={{animationDelay: '0.2s'}}>
          <div className="enterprise-stat-value" style={{color: 'var(--warning-color)'}}>{attackPaths.length}</div>
          <div className="enterprise-stat-label">Attack Scenarios</div>
          <Target style={{width: '2rem', height: '2rem', color: 'var(--warning-color)', margin: '0.5rem auto 0'}} />
        </div>
        
        <div className="enterprise-stat-card animate-slide-up" style={{animationDelay: '0.3s'}}>
          <div className="enterprise-stat-value" style={{color: 'var(--success-color)'}}>
            {riskData.length > 0 ? Math.round(riskData.reduce((sum, item) => sum + item.risk_score, 0) / riskData.length * 10) / 10 : 0}
          </div>
          <div className="enterprise-stat-label">Average Risk Score</div>
          <BarChart3 style={{width: '2rem', height: '2rem', color: 'var(--success-color)', margin: '0.5rem auto 0'}} />
        </div>
      </div>

      {/* Visualization Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} style={{width: '100%'}}>
        <div style={{display: 'flex', gap: '0.5rem', marginBottom: '2rem', padding: '0.5rem', background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-color)'}}>
          <TabsTrigger value="network" style={{flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1rem'}}>
            <Network style={{width: '1rem', height: '1rem'}} />
            Network Topology
          </TabsTrigger>
          <TabsTrigger value="attack" style={{flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1rem'}}>
            <Target style={{width: '1rem', height: '1rem'}} />
            Attack Paths
          </TabsTrigger>
          <TabsTrigger value="risk" style={{flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1rem'}}>
            <BarChart3 style={{width: '1rem', height: '1rem'}} />
            Risk Analysis
          </TabsTrigger>
        </div>

        {/* Network Topology Tab */}
        <TabsContent value="network">
          <div className="enterprise-card animate-slide-up">
            <div className="enterprise-card-header">
              <h3 style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
                <Network style={{width: '1.5rem', height: '1.5rem'}} />
                Interactive Network Topology
              </h3>
              <p style={{margin: '0.5rem 0 0 0', opacity: 0.9}}>
                Explore your network infrastructure with vulnerability overlays and real-time interactions.
                Click on nodes to see details, use controls to zoom and filter.
              </p>
            </div>
            <div className="enterprise-card-body">
              {networkData && (
                <NetworkTopologyVisualization
                  networkData={networkData}
                  vulnerabilities={vulnerabilities}
                  onNodeClick={handleNodeClick}
                  height={600}
                  width={1200}
                  showVulnerabilities={true}
                  showServices={true}
                />
              )}
            </div>
          </div>
        </TabsContent>

        {/* Attack Paths Tab */}
        <TabsContent value="attack">
          <div className="enterprise-card animate-slide-up">
            <div className="enterprise-card-header">
              <h3 style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
                <Target style={{width: '1.5rem', height: '1.5rem'}} />
                Attack Path Visualization
              </h3>
              <p style={{margin: '0.5rem 0 0 0', opacity: 0.9}}>
                Analyze potential attack scenarios with MITRE ATT&CK framework integration.
                Select an attack path and use playback controls to step through the attack sequence.
              </p>
            </div>
            <div className="enterprise-card-body">
              <AttackPathVisualization
                attackPaths={attackPaths}
                networkNodes={networkData?.nodes || []}
                vulnerabilities={vulnerabilities}
                onPathSelect={handlePathSelect}
                height={700}
                width={1200}
                autoPlay={false}
                showRiskScores={true}
              />
            </div>
          </div>
        </TabsContent>

        {/* Risk Analysis Tab */}
        <TabsContent value="risk">
          <div className="enterprise-card animate-slide-up">
            <div className="enterprise-card-header">
              <h3 style={{display: 'flex', alignItems: 'center', gap: '0.75rem'}}>
                <BarChart3 style={{width: '1.5rem', height: '1.5rem'}} />
                Risk Heat Map Analysis
              </h3>
              <p style={{margin: '0.5rem 0 0 0', opacity: 0.9}}>
                Visualize security risks across different dimensions with interactive heat maps.
                Use filters to group by asset, service, or time periods.
              </p>
            </div>
            <div className="enterprise-card-body">
              <RiskHeatMapVisualization
                riskData={riskData}
                timeRange="30d"
                groupBy="asset"
                metricType="vulnerability_count"
                onCellClick={handleCellClick}
                height={500}
                width={1200}
                showLegend={true}
                showLabels={true}
              />
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Quick Actions */}
      <div className="enterprise-card animate-slide-up" style={{marginTop: '2rem'}}>
        <div className="enterprise-card-header">
          <h3>Security Operations Center</h3>
        </div>
        <div className="enterprise-card-body">
          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem'}}>
            <button className="enterprise-btn enterprise-btn-primary">
              <Network style={{width: '1rem', height: '1rem'}} />
              Refresh Network Data
            </button>
            <button className="enterprise-btn enterprise-btn-outline">
              <Target style={{width: '1rem', height: '1rem'}} />
              Generate Attack Scenarios
            </button>
            <button className="enterprise-btn enterprise-btn-outline">
              <BarChart3 style={{width: '1rem', height: '1rem'}} />
              Export Risk Report
            </button>
            <button className="enterprise-btn enterprise-btn-primary">
              <Shield style={{width: '1rem', height: '1rem'}} />
              Run Security Scan
            </button>
          </div>
        </div>
      </div>


    </div>
  );
};

export default VisualizationDashboard;