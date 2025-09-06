import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { fetchEnterpriseDashboard, exportToBI } from '../services/api';

const DashboardPage = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const svgRef = useRef();

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws/attack-matrix');
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setAttackMatrix(prev => ({...prev, ...data}));
    };
    
    const fetchEnterpriseData = async () => {
      try {
        const response = await axios.get('/api/enterprise-dashboard', {
          params: { timeframe: '7d', businessUnit: selectedUnit }
        });
        
        setAttackCoverage(processMitreData(response.data.attack_matrix));
        setRiskTrends(formatTrendData(response.data.risk_timeline));
        setFinancialExposure(response.data.financial_metrics);
      } catch (error) {
        setError('Failed to load enterprise security dashboard');
      }
    };

    fetchEnterpriseData();
    return () => ws.close();
  }, [selectedUnit]);

  const processMitreData = (matrix) => {
    return Object.entries(matrix).map(([technique, coverage]) => ({
      technique,
      coverage: coverage * 100,
      color: coverage > 0.8 ? '#4CAF50' : coverage > 0.5 ? '#FFC107' : '#F44336'
    }));
  };

  fetchEnterpriseDashboard()
      .then(data => {
        if (data?.attack_coverage?.length && data?.risk_trends?.length) {
          setDashboardData(data);
          renderAttackMatrix(data.attack_coverage);
          renderRiskTimeline(data.risk_trends);
        }
      })
      .catch(error => console.error('Dashboard load error:', error));
  }, []);

  const renderAttackMatrix = (matrixData) => {
    const svg = d3.select(svgRef.current);
    const width = 800, height = 600;
    
    // MITRE ATT&CK Heatmap implementation
    const colorScale = d3.scaleSequential()
      .domain([0, d3.max(matrixData, d => d.value)])
      .interpolator(d3.interpolateYlOrRd);

    svg.selectAll('rect')
      .data(matrixData)
      .enter()
      .append('rect')
      .attr('x', d => d.x * 100)
      .attr('y', d => d.y * 50)
      .attr('width', 95)
      .attr('height', 45)
      .attr('fill', d => colorScale(d.value))
      .attr('stroke', '#333');
  };

  const renderRiskTimeline = (timelineData) => {
    const svg = d3.select(svgRef.current);
    const margin = { top: 20, right: 30, bottom: 30, left: 40 };
    const width = 800 - margin.left - margin.right;
    const height = 200 - margin.top - margin.bottom;

    const x = d3.scaleTime()
      .domain(d3.extent(timelineData, d => new Date(d.date)))
      .range([margin.left, width - margin.right]);

    const y = d3.scaleLinear()
      .domain([0, d3.max(timelineData, d => d.value)])
      .range([height - margin.bottom, margin.top]);

    svg.append('path')
      .datum(timelineData)
      .attr('fill', 'none')
      .attr('stroke', 'steelblue')
      .attr('stroke-width', 1.5)
      .attr('d', d3.line()
        .x(d => x(new Date(d.date)))
        .y(d => y(d.value))
      );
  };

  // Add additional visualization methods
  const renderComplianceGauge = (complianceScore) => {
    const svg = d3.select('#compliance-gauge');
    svg.selectAll('*').remove();
    
    const width = 300, height = 200;
    const arc = d3.arc()
      .innerRadius(60)
      .outerRadius(80)
      .startAngle(-Math.PI / 2)
      .endAngle(Math.PI / 2 * complianceScore);

    svg.append('path')
      .attr('d', arc)
      .attr('transform', `translate(${width/2}, ${height/2})`)
      .attr('fill', complianceScore > 0.8 ? '#4CAF50' : complianceScore > 0.6 ? '#FFC107' : '#F44336');

    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height / 2 + 10)
      .attr('text-anchor', 'middle')
      .attr('class', 'gauge-score')
      .text(`${(complianceScore * 100).toFixed(1)}%`);
  };

  const renderThreatPieChart = (threatData) => {
    const svg = d3.select('#threat-pie');
    svg.selectAll('*').remove();
    
    const width = 300, height = 200;
    const radius = Math.min(width, height) / 2;
    
    const pie = d3.pie().value(d => d.value);
    const arc = d3.arc().innerRadius(0).outerRadius(radius);
    
    const color = d3.scaleOrdinal(d3.schemeCategory10);
    
    const arcs = svg.selectAll('arc')
      .data(pie(threatData))
      .enter()
      .append('g')
      .attr('transform', `translate(${width/2}, ${height/2})`);
    
    arcs.append('path')
      .attr('d', arc)
      .attr('fill', (d, i) => color(i));
  };

  // Initialize all visualizations when data loads
  useEffect(() => {
    if (dashboardData) {
      renderAttackMatrix(dashboardData.attack_coverage);
      renderRiskTimeline(dashboardData.risk_trends);
      renderComplianceGauge(dashboardData.compliance_score || 0.85);
      renderThreatPieChart([
        {category: 'Malware', value: 35},
        {category: 'Phishing', value: 25},
        {category: 'Insider', value: 15},
        {category: 'DDoS', value: 10},
        {category: 'Other', value: 15}
      ]);
    }
  }, [dashboardData]);

  return (
    <div className="enterprise-dashboard">
      <div className="dashboard-section real-time-indicator">
          <h3>MITRE ATT&CK® Real-Time Matrix
            <span className="live-pulse" />
          </h3>
          <div className="mitre-matrix">
          <svg ref={svgRef} width={800} height={600} />
          </div>
        </div>
      <div className="bi-integration">
        <button 
          className="powerbi-export"
          onClick={() => exportToBI('powerbi')}
        >
          Export to Power BI
        </button>
        <button
          className="tableau-export"
          onClick={() => exportToBI('tableau')}
        >
          Export to Tableau
        </button>
      </div>
    </div>
  );
};

export default DashboardPage;