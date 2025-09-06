import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { Download, Filter, BarChart3, TrendingUp, AlertTriangle, Shield } from 'lucide-react';

const RiskHeatMapVisualization = ({ 
  riskData = [],
  timeRange = '30d',
  groupBy = 'asset',
  metricType = 'vulnerability_count',
  onCellClick,
  onCellHover,
  height = 500,
  width = 800,
  showLegend = true,
  showLabels = true
}) => {
  const svgRef = useRef();
  const [selectedCell, setSelectedCell] = useState(null);
  const [hoveredCell, setHoveredCell] = useState(null);
  const [processedData, setProcessedData] = useState([]);
  const [colorScale, setColorScale] = useState(null);
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, content: '' });
  const [viewMode, setViewMode] = useState('heatmap'); // heatmap, treemap, matrix

  // Color schemes for different risk levels
  const colorSchemes = {
    risk: ['#f0f9ff', '#e0f2fe', '#bae6fd', '#7dd3fc', '#38bdf8', '#0ea5e9', '#0284c7', '#0369a1', '#075985', '#0c4a6e'],
    vulnerability: ['#fef2f2', '#fee2e2', '#fecaca', '#fca5a5', '#f87171', '#ef4444', '#dc2626', '#b91c1c', '#991b1b', '#7f1d1d'],
    severity: ['#f0fdf4', '#dcfce7', '#bbf7d0', '#86efac', '#4ade80', '#22c55e', '#16a34a', '#15803d', '#166534', '#14532d'],
    compliance: ['#fffbeb', '#fef3c7', '#fde68a', '#fcd34d', '#fbbf24', '#f59e0b', '#d97706', '#b45309', '#92400e', '#78350f']
  };

  // Process data based on groupBy and metricType
  useEffect(() => {
    if (!riskData || riskData.length === 0) return;

    let processed = [];

    if (groupBy === 'asset') {
      // Group by asset (IP/hostname)
      const assetGroups = d3.group(riskData, d => d.asset || d.ip || d.hostname);
      
      assetGroups.forEach((values, asset) => {
        const metrics = calculateMetrics(values, metricType);
        processed.push({
          id: asset,
          label: asset,
          value: metrics.value,
          count: values.length,
          severity: metrics.severity,
          details: metrics.details,
          rawData: values
        });
      });
    } else if (groupBy === 'service') {
      // Group by service/port
      const serviceGroups = d3.group(riskData, d => `${d.service || 'unknown'}:${d.port || 'unknown'}`);
      
      serviceGroups.forEach((values, service) => {
        const metrics = calculateMetrics(values, metricType);
        processed.push({
          id: service,
          label: service,
          value: metrics.value,
          count: values.length,
          severity: metrics.severity,
          details: metrics.details,
          rawData: values
        });
      });
    } else if (groupBy === 'vulnerability_type') {
      // Group by vulnerability type
      const typeGroups = d3.group(riskData, d => d.type || d.category || 'unknown');
      
      typeGroups.forEach((values, type) => {
        const metrics = calculateMetrics(values, metricType);
        processed.push({
          id: type,
          label: type,
          value: metrics.value,
          count: values.length,
          severity: metrics.severity,
          details: metrics.details,
          rawData: values
        });
      });
    } else if (groupBy === 'time') {
      // Group by time periods
      const timeGroups = d3.group(riskData, d => {
        const date = new Date(d.created_at || d.timestamp);
        if (timeRange === '24h') {
          return d3.timeHour.floor(date).toISOString();
        } else if (timeRange === '7d') {
          return d3.timeDay.floor(date).toISOString();
        } else {
          return d3.timeWeek.floor(date).toISOString();
        }
      });
      
      timeGroups.forEach((values, time) => {
        const metrics = calculateMetrics(values, metricType);
        const date = new Date(time);
        processed.push({
          id: time,
          label: formatTimeLabel(date, timeRange),
          value: metrics.value,
          count: values.length,
          severity: metrics.severity,
          details: metrics.details,
          rawData: values,
          timestamp: date
        });
      });
    }

    // Sort by value descending
    processed.sort((a, b) => b.value - a.value);
    
    setProcessedData(processed);

    // Create color scale
    const maxValue = d3.max(processed, d => d.value) || 1;
    const scheme = getColorScheme(metricType);
    const scale = d3.scaleSequential(d3.interpolateRgb(scheme[0], scheme[scheme.length - 1]))
      .domain([0, maxValue]);
    
    setColorScale(() => scale);

  }, [riskData, groupBy, metricType, timeRange]);

  // Calculate metrics based on metric type
  const calculateMetrics = (data, type) => {
    let value, severity, details;

    switch (type) {
      case 'vulnerability_count':
        value = data.length;
        severity = calculateAverageSeverity(data);
        details = {
          critical: data.filter(d => d.severity === 'critical').length,
          high: data.filter(d => d.severity === 'high').length,
          medium: data.filter(d => d.severity === 'medium').length,
          low: data.filter(d => d.severity === 'low').length
        };
        break;
      
      case 'risk_score':
        value = d3.mean(data, d => d.risk_score || d.cvss_score || 0) || 0;
        severity = value >= 7 ? 'high' : value >= 4 ? 'medium' : 'low';
        details = {
          avg_score: value,
          max_score: d3.max(data, d => d.risk_score || d.cvss_score || 0),
          min_score: d3.min(data, d => d.risk_score || d.cvss_score || 0)
        };
        break;
      
      case 'compliance_score':
        value = d3.mean(data, d => d.compliance_score || 0) || 0;
        severity = value >= 80 ? 'low' : value >= 60 ? 'medium' : 'high';
        details = {
          avg_compliance: value,
          passing: data.filter(d => (d.compliance_score || 0) >= 80).length,
          failing: data.filter(d => (d.compliance_score || 0) < 80).length
        };
        break;
      
      case 'exposure_time':
        const avgExposure = d3.mean(data, d => {
          const created = new Date(d.created_at || d.timestamp);
          const resolved = d.resolved_at ? new Date(d.resolved_at) : new Date();
          return (resolved - created) / (1000 * 60 * 60 * 24); // days
        }) || 0;
        value = avgExposure;
        severity = avgExposure > 30 ? 'high' : avgExposure > 7 ? 'medium' : 'low';
        details = {
          avg_days: avgExposure,
          max_days: d3.max(data, d => {
            const created = new Date(d.created_at || d.timestamp);
            const resolved = d.resolved_at ? new Date(d.resolved_at) : new Date();
            return (resolved - created) / (1000 * 60 * 60 * 24);
          }),
          unresolved: data.filter(d => !d.resolved_at).length
        };
        break;
      
      default:
        value = data.length;
        severity = 'medium';
        details = { count: data.length };
    }

    return { value: Math.round(value * 100) / 100, severity, details };
  };

  // Calculate average severity
  const calculateAverageSeverity = (data) => {
    const severityWeights = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const avgWeight = d3.mean(data, d => severityWeights[d.severity] || 1) || 1;
    
    if (avgWeight >= 3.5) return 'critical';
    if (avgWeight >= 2.5) return 'high';
    if (avgWeight >= 1.5) return 'medium';
    return 'low';
  };

  // Get color scheme based on metric type
  const getColorScheme = (type) => {
    switch (type) {
      case 'risk_score':
      case 'vulnerability_count':
        return colorSchemes.vulnerability;
      case 'compliance_score':
        return colorSchemes.compliance;
      case 'exposure_time':
        return colorSchemes.risk;
      default:
        return colorSchemes.risk;
    }
  };

  // Format time labels
  const formatTimeLabel = (date, range) => {
    if (range === '24h') {
      return d3.timeFormat('%H:%M')(date);
    } else if (range === '7d') {
      return d3.timeFormat('%a %d')(date);
    } else {
      return d3.timeFormat('%b %d')(date);
    }
  };

  // Initialize D3 visualization
  useEffect(() => {
    if (!processedData || processedData.length === 0 || !colorScale) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const margin = { top: 40, right: 40, bottom: 60, left: 100 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    if (viewMode === 'heatmap') {
      renderHeatMap(g, innerWidth, innerHeight);
    } else if (viewMode === 'treemap') {
      renderTreeMap(g, innerWidth, innerHeight);
    } else if (viewMode === 'matrix') {
      renderMatrix(g, innerWidth, innerHeight);
    }

  }, [processedData, colorScale, viewMode, selectedCell]);

  // Render heat map
  const renderHeatMap = (g, width, height) => {
    const cellSize = Math.min(width / Math.ceil(Math.sqrt(processedData.length)), 60);
    const cols = Math.floor(width / cellSize);
    const rows = Math.ceil(processedData.length / cols);

    const cells = g.selectAll('.heat-cell')
      .data(processedData)
      .enter().append('g')
      .attr('class', 'heat-cell')
      .attr('transform', (d, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        return `translate(${col * cellSize},${row * cellSize})`;
      });

    // Add cell rectangles
    cells.append('rect')
      .attr('width', cellSize - 2)
      .attr('height', cellSize - 2)
      .attr('fill', d => colorScale(d.value))
      .attr('stroke', d => selectedCell?.id === d.id ? '#000' : '#fff')
      .attr('stroke-width', d => selectedCell?.id === d.id ? 3 : 1)
      .attr('rx', 4)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        setSelectedCell(d);
        if (onCellClick) onCellClick(d);
      })
      .on('mouseover', (event, d) => {
        setHoveredCell(d);
        showTooltip(event, d);
        if (onCellHover) onCellHover(d);
      })
      .on('mouseout', () => {
        setHoveredCell(null);
        hideTooltip();
      });

    // Add cell labels
    if (showLabels && cellSize > 40) {
      cells.append('text')
        .attr('x', cellSize / 2)
        .attr('y', cellSize / 2 - 5)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('font-size', Math.min(cellSize / 6, 12))
        .attr('font-weight', 'bold')
        .attr('fill', d => d.value > colorScale.domain()[1] / 2 ? '#fff' : '#000')
        .text(d => d.label.length > 8 ? d.label.substring(0, 8) + '...' : d.label);

      cells.append('text')
        .attr('x', cellSize / 2)
        .attr('y', cellSize / 2 + 8)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('font-size', Math.min(cellSize / 8, 10))
        .attr('fill', d => d.value > colorScale.domain()[1] / 2 ? '#fff' : '#000')
        .text(d => d.value);
    }
  };

  // Render tree map
  const renderTreeMap = (g, width, height) => {
    const hierarchy = d3.hierarchy({ children: processedData })
      .sum(d => d.value || 0)
      .sort((a, b) => b.value - a.value);

    const treemap = d3.treemap()
      .size([width, height])
      .padding(2)
      .round(true);

    treemap(hierarchy);

    const cells = g.selectAll('.tree-cell')
      .data(hierarchy.leaves())
      .enter().append('g')
      .attr('class', 'tree-cell')
      .attr('transform', d => `translate(${d.x0},${d.y0})`);

    cells.append('rect')
      .attr('width', d => d.x1 - d.x0)
      .attr('height', d => d.y1 - d.y0)
      .attr('fill', d => colorScale(d.data.value))
      .attr('stroke', '#fff')
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        setSelectedCell(d.data);
        if (onCellClick) onCellClick(d.data);
      })
      .on('mouseover', (event, d) => {
        showTooltip(event, d.data);
      })
      .on('mouseout', hideTooltip);

    // Add labels for larger cells
    cells.filter(d => (d.x1 - d.x0) > 50 && (d.y1 - d.y0) > 30)
      .append('text')
      .attr('x', d => (d.x1 - d.x0) / 2)
      .attr('y', d => (d.y1 - d.y0) / 2)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .attr('fill', '#fff')
      .text(d => d.data.label);
  };

  // Render matrix view
  const renderMatrix = (g, width, height) => {
    // This would implement a matrix view for correlation analysis
    // For now, fall back to heatmap
    renderHeatMap(g, width, height);
  };

  // Tooltip functions
  const showTooltip = (event, data) => {
    const content = `${data.label}\nValue: ${data.value}\nCount: ${data.count}\nSeverity: ${data.severity}`;
    setTooltip({
      visible: true,
      x: event.pageX + 10,
      y: event.pageY - 10,
      content
    });
  };

  const hideTooltip = () => {
    setTooltip({ visible: false, x: 0, y: 0, content: '' });
  };

  // Export function
  const handleExport = useCallback(() => {
    const svg = svgRef.current;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `risk-heatmap-${groupBy}-${metricType}.svg`;
    link.click();
    URL.revokeObjectURL(url);
  }, [groupBy, metricType]);

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-blue-500" />
            Risk Heat Map
            {processedData.length > 0 && (
              <Badge variant="secondary">
                {processedData.length} items
              </Badge>
            )}
          </CardTitle>
          
          <div className="flex items-center gap-2">
            {/* View Mode */}
            <select
              value={viewMode}
              onChange={(e) => setViewMode(e.target.value)}
              className="px-3 py-1 border rounded text-sm"
            >
              <option value="heatmap">Heat Map</option>
              <option value="treemap">Tree Map</option>
              <option value="matrix">Matrix</option>
            </select>
            
            {/* Group By */}
            <select
              value={groupBy}
              onChange={(e) => {
                // This would be handled by parent component
                console.log('Group by changed:', e.target.value);
              }}
              className="px-3 py-1 border rounded text-sm"
            >
              <option value="asset">By Asset</option>
              <option value="service">By Service</option>
              <option value="vulnerability_type">By Vuln Type</option>
              <option value="time">By Time</option>
            </select>
            
            {/* Metric Type */}
            <select
              value={metricType}
              onChange={(e) => {
                // This would be handled by parent component
                console.log('Metric type changed:', e.target.value);
              }}
              className="px-3 py-1 border rounded text-sm"
            >
              <option value="vulnerability_count">Vuln Count</option>
              <option value="risk_score">Risk Score</option>
              <option value="compliance_score">Compliance</option>
              <option value="exposure_time">Exposure Time</option>
            </select>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={handleExport}>
                    <Download className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Export</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-4">
          {/* Statistics */}
          {processedData.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">
                  {processedData.length}
                </div>
                <div className="text-sm text-gray-600">Total Items</div>
              </div>
              
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">
                  {processedData.filter(d => d.severity === 'critical' || d.severity === 'high').length}
                </div>
                <div className="text-sm text-gray-600">High Risk</div>
              </div>
              
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">
                  {Math.round(d3.mean(processedData, d => d.value) * 100) / 100 || 0}
                </div>
                <div className="text-sm text-gray-600">Avg Value</div>
              </div>
              
              <div className="text-center p-3 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">
                  {d3.max(processedData, d => d.value) || 0}
                </div>
                <div className="text-sm text-gray-600">Max Value</div>
              </div>
            </div>
          )}
          
          {/* Visualization */}
          <div className="relative">
            {processedData.length > 0 ? (
              <>
                <svg
                  ref={svgRef}
                  width={width}
                  height={height}
                  className="border rounded-lg bg-white"
                />
                
                {/* Tooltip */}
                {tooltip.visible && (
                  <div
                    className="absolute z-10 bg-black text-white text-xs rounded px-2 py-1 pointer-events-none whitespace-pre-line"
                    style={{
                      left: tooltip.x,
                      top: tooltip.y,
                      transform: 'translate(-50%, -100%)'
                    }}
                  >
                    {tooltip.content}
                  </div>
                )}
                
                {/* Legend */}
                {showLegend && colorScale && (
                  <div className="absolute top-4 right-4 bg-white p-3 rounded-lg shadow border">
                    <h4 className="font-semibold text-sm mb-2">Risk Level</h4>
                    <div className="space-y-1">
                      {[0, 0.25, 0.5, 0.75, 1].map((t, i) => {
                        const value = colorScale.domain()[0] + t * (colorScale.domain()[1] - colorScale.domain()[0]);
                        return (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <div 
                              className="w-4 h-4 rounded"
                              style={{ backgroundColor: colorScale(value) }}
                            ></div>
                            <span>{Math.round(value * 100) / 100}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-gray-500">
                <BarChart3 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No risk data available for visualization</p>
              </div>
            )}
          </div>
          
          {/* Selected Cell Details */}
          {selectedCell && (
            <div className="bg-gray-50 p-4 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold">Selected: {selectedCell.label}</h4>
                <Badge 
                  variant={selectedCell.severity === 'critical' || selectedCell.severity === 'high' ? 'destructive' : 'secondary'}
                >
                  {selectedCell.severity}
                </Badge>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <strong>Value:</strong> {selectedCell.value}
                </div>
                <div>
                  <strong>Count:</strong> {selectedCell.count}
                </div>
                <div>
                  <strong>Severity:</strong> {selectedCell.severity}
                </div>
                <div>
                  <strong>Items:</strong> {selectedCell.rawData?.length || 0}
                </div>
              </div>
              
              {selectedCell.details && (
                <div className="mt-3">
                  <strong>Details:</strong>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-1 text-sm">
                    {Object.entries(selectedCell.details).map(([key, value]) => (
                      <div key={key} className="flex justify-between">
                        <span className="text-gray-600">{key}:</span>
                        <span className="font-medium">{typeof value === 'number' ? Math.round(value * 100) / 100 : value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default RiskHeatMapVisualization;