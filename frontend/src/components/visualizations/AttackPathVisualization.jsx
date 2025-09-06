import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { Play, Pause, RotateCcw, Download, Filter, AlertTriangle, Target, Shield } from 'lucide-react';

const AttackPathVisualization = ({ 
  attackPaths = [], 
  networkNodes = [],
  vulnerabilities = [],
  onPathSelect,
  onStepSelect,
  height = 700,
  width = 1000,
  autoPlay = false,
  showRiskScores = true
}) => {
  const svgRef = useRef();
  const [selectedPath, setSelectedPath] = useState(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(autoPlay);
  const [playbackSpeed, setPlaybackSpeed] = useState(1000); // ms
  const [filteredPaths, setFilteredPaths] = useState(attackPaths);
  const [riskFilter, setRiskFilter] = useState('all');
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, content: '' });

  // Attack technique colors based on MITRE ATT&CK framework
  const techniqueColors = {
    'initial-access': '#dc2626',
    'execution': '#ea580c',
    'persistence': '#d97706',
    'privilege-escalation': '#ca8a04',
    'defense-evasion': '#65a30d',
    'credential-access': '#16a34a',
    'discovery': '#059669',
    'lateral-movement': '#0891b2',
    'collection': '#0284c7',
    'command-control': '#2563eb',
    'exfiltration': '#7c3aed',
    'impact': '#c026d3'
  };

  // Risk level colors
  const riskColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#65a30d'
  };

  // Filter attack paths based on risk level
  useEffect(() => {
    if (riskFilter === 'all') {
      setFilteredPaths(attackPaths);
    } else {
      setFilteredPaths(attackPaths.filter(path => path.riskLevel === riskFilter));
    }
  }, [attackPaths, riskFilter]);

  // Auto-play functionality
  useEffect(() => {
    let interval;
    if (isPlaying && selectedPath && selectedPath.steps) {
      interval = setInterval(() => {
        setCurrentStep(prev => {
          if (prev >= selectedPath.steps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, playbackSpeed);
    }
    return () => clearInterval(interval);
  }, [isPlaying, selectedPath, playbackSpeed]);

  // Initialize D3 visualization
  useEffect(() => {
    if (!selectedPath || !selectedPath.steps) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Set up dimensions
    const margin = { top: 40, right: 40, bottom: 40, left: 40 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Create main group
    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Create timeline scale
    const timeScale = d3.scaleLinear()
      .domain([0, selectedPath.steps.length - 1])
      .range([0, innerWidth]);

    // Create vertical position scale for different attack vectors
    const vectorScale = d3.scaleBand()
      .domain(['network', 'host', 'application', 'social'])
      .range([0, innerHeight])
      .padding(0.1);

    // Draw timeline axis
    const timeAxis = d3.axisBottom(timeScale)
      .tickFormat(d => `Step ${d + 1}`);
    
    g.append('g')
      .attr('class', 'time-axis')
      .attr('transform', `translate(0,${innerHeight + 10})`)
      .call(timeAxis);

    // Draw attack vector lanes
    g.selectAll('.vector-lane')
      .data(['network', 'host', 'application', 'social'])
      .enter().append('rect')
      .attr('class', 'vector-lane')
      .attr('x', 0)
      .attr('y', d => vectorScale(d))
      .attr('width', innerWidth)
      .attr('height', vectorScale.bandwidth())
      .attr('fill', (d, i) => d3.schemeCategory10[i % 10])
      .attr('fill-opacity', 0.1)
      .attr('stroke', (d, i) => d3.schemeCategory10[i % 10])
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '2,2');

    // Add vector lane labels
    g.selectAll('.vector-label')
      .data(['network', 'host', 'application', 'social'])
      .enter().append('text')
      .attr('class', 'vector-label')
      .attr('x', -10)
      .attr('y', d => vectorScale(d) + vectorScale.bandwidth() / 2)
      .attr('text-anchor', 'end')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .attr('fill', '#374151')
      .text(d => d.charAt(0).toUpperCase() + d.slice(1));

    // Create step nodes
    const stepNodes = g.selectAll('.step-node')
      .data(selectedPath.steps)
      .enter().append('g')
      .attr('class', 'step-node')
      .attr('transform', (d, i) => {
        const x = timeScale(i);
        const y = vectorScale(d.vector || 'network') + vectorScale.bandwidth() / 2;
        return `translate(${x},${y})`;
      });

    // Add step circles
    stepNodes.append('circle')
      .attr('r', 20)
      .attr('fill', d => techniqueColors[d.technique] || '#6b7280')
      .attr('stroke', '#fff')
      .attr('stroke-width', 3)
      .attr('opacity', (d, i) => i <= currentStep ? 1 : 0.3)
      .style('cursor', 'pointer')
      .on('click', (event, d, i) => {
        setCurrentStep(i);
        if (onStepSelect) onStepSelect(d, i);
      })
      .on('mouseover', (event, d) => {
        showTooltip(event, `${d.title}\nTechnique: ${d.technique}\nRisk: ${d.riskScore}/10\nDescription: ${d.description}`);
      })
      .on('mouseout', hideTooltip);

    // Add step icons
    stepNodes.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .attr('fill', '#fff')
      .text((d, i) => i + 1);

    // Add step labels
    stepNodes.append('text')
      .attr('y', 35)
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('font-weight', 'bold')
      .attr('fill', '#374151')
      .text(d => d.title);

    // Add risk scores if enabled
    if (showRiskScores) {
      stepNodes.append('circle')
        .attr('cx', 15)
        .attr('cy', -15)
        .attr('r', 8)
        .attr('fill', d => {
          if (d.riskScore >= 8) return riskColors.critical;
          if (d.riskScore >= 6) return riskColors.high;
          if (d.riskScore >= 4) return riskColors.medium;
          return riskColors.low;
        })
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);

      stepNodes.append('text')
        .attr('x', 15)
        .attr('y', -11)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px')
        .attr('font-weight', 'bold')
        .attr('fill', '#fff')
        .text(d => d.riskScore);
    }

    // Draw connections between steps
    const connections = g.selectAll('.step-connection')
      .data(selectedPath.steps.slice(0, -1))
      .enter().append('line')
      .attr('class', 'step-connection')
      .attr('x1', (d, i) => timeScale(i) + 20)
      .attr('y1', (d, i) => {
        const step = selectedPath.steps[i];
        return vectorScale(step.vector || 'network') + vectorScale.bandwidth() / 2;
      })
      .attr('x2', (d, i) => timeScale(i + 1) - 20)
      .attr('y2', (d, i) => {
        const nextStep = selectedPath.steps[i + 1];
        return vectorScale(nextStep.vector || 'network') + vectorScale.bandwidth() / 2;
      })
      .attr('stroke', '#6b7280')
      .attr('stroke-width', 3)
      .attr('stroke-opacity', (d, i) => i < currentStep ? 1 : 0.3)
      .attr('marker-end', 'url(#arrowhead)');

    // Create arrow marker
    const defs = svg.append('defs');
    defs.append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 8)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#6b7280');

    // Add current step highlight
    if (currentStep < selectedPath.steps.length) {
      const currentStepData = selectedPath.steps[currentStep];
      const x = timeScale(currentStep);
      const y = vectorScale(currentStepData.vector || 'network') + vectorScale.bandwidth() / 2;
      
      g.append('circle')
        .attr('cx', x)
        .attr('cy', y)
        .attr('r', 30)
        .attr('fill', 'none')
        .attr('stroke', '#fbbf24')
        .attr('stroke-width', 3)
        .attr('stroke-dasharray', '5,5')
        .style('animation', 'pulse 2s infinite');
    }

    // Add affected assets for current step
    if (currentStep < selectedPath.steps.length) {
      const currentStepData = selectedPath.steps[currentStep];
      if (currentStepData.affectedAssets) {
        const assetGroup = g.append('g')
          .attr('class', 'affected-assets');
        
        currentStepData.affectedAssets.forEach((asset, index) => {
          const assetX = timeScale(currentStep) + 50 + (index * 30);
          const assetY = vectorScale(currentStepData.vector || 'network') + vectorScale.bandwidth() / 2;
          
          assetGroup.append('rect')
            .attr('x', assetX - 10)
            .attr('y', assetY - 10)
            .attr('width', 20)
            .attr('height', 20)
            .attr('fill', '#ef4444')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .attr('rx', 3);
          
          assetGroup.append('text')
            .attr('x', assetX)
            .attr('y', assetY + 25)
            .attr('text-anchor', 'middle')
            .attr('font-size', '9px')
            .attr('fill', '#374151')
            .text(asset.name || asset.ip);
        });
      }
    }

    // Tooltip functions
    function showTooltip(event, content) {
      setTooltip({
        visible: true,
        x: event.pageX + 10,
        y: event.pageY - 10,
        content
      });
    }

    function hideTooltip() {
      setTooltip({ visible: false, x: 0, y: 0, content: '' });
    }

  }, [selectedPath, currentStep, showRiskScores]);

  // Control functions
  const handlePlay = useCallback(() => {
    setIsPlaying(!isPlaying);
  }, [isPlaying]);

  const handleReset = useCallback(() => {
    setCurrentStep(0);
    setIsPlaying(false);
  }, []);

  const handleStepForward = useCallback(() => {
    if (selectedPath && currentStep < selectedPath.steps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  }, [selectedPath, currentStep]);

  const handleStepBackward = useCallback(() => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  }, [currentStep]);

  const handleExport = useCallback(() => {
    const svg = svgRef.current;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `attack-path-${selectedPath?.id || 'visualization'}.svg`;
    link.click();
    URL.revokeObjectURL(url);
  }, [selectedPath]);

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            Attack Path Analysis
            {selectedPath && (
              <Badge variant="secondary">
                {selectedPath.steps?.length || 0} steps
              </Badge>
            )}
          </CardTitle>
          
          <div className="flex items-center gap-2">
            {/* Risk Filter */}
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="px-3 py-1 border rounded text-sm"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            
            {/* Playback Controls */}
            {selectedPath && (
              <>
                <Button variant="outline" size="sm" onClick={handleStepBackward} disabled={currentStep === 0}>
                  ←
                </Button>
                
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button variant="outline" size="sm" onClick={handlePlay}>
                        {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>{isPlaying ? 'Pause' : 'Play'}</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={handleStepForward} 
                  disabled={!selectedPath || currentStep >= selectedPath.steps.length - 1}
                >
                  →
                </Button>
                
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button variant="outline" size="sm" onClick={handleReset}>
                        <RotateCcw className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Reset</TooltipContent>
                  </Tooltip>
                </TooltipProvider>
                
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
              </>
            )}
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-4">
          {/* Attack Path Selection */}
          {filteredPaths.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2">Available Attack Paths</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {filteredPaths.map((path, index) => (
                  <div
                    key={path.id || index}
                    className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                      selectedPath?.id === path.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => {
                      setSelectedPath(path);
                      setCurrentStep(0);
                      setIsPlaying(false);
                      if (onPathSelect) onPathSelect(path);
                    }}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h5 className="font-medium text-sm">{path.name}</h5>
                      <Badge 
                        variant={path.riskLevel === 'critical' ? 'destructive' : 'secondary'}
                        className="text-xs"
                      >
                        {path.riskLevel}
                      </Badge>
                    </div>
                    
                    <p className="text-xs text-gray-600 mb-2">{path.description}</p>
                    
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>{path.steps?.length || 0} steps</span>
                      <span>Risk: {path.overallRisk}/10</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Visualization */}
          {selectedPath ? (
            <div className="relative">
              <svg
                ref={svgRef}
                width={width}
                height={height}
                className="border rounded-lg bg-gray-50"
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
              
              {/* Progress indicator */}
              <div className="absolute top-4 left-4 bg-white p-2 rounded-lg shadow border">
                <div className="text-sm font-medium mb-1">
                  Step {currentStep + 1} of {selectedPath.steps?.length || 0}
                </div>
                <div className="w-48 bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${((currentStep + 1) / (selectedPath.steps?.length || 1)) * 100}%` }}
                  ></div>
                </div>
              </div>
              
              {/* Legend */}
              <div className="absolute top-4 right-4 bg-white p-3 rounded-lg shadow border">
                <h4 className="font-semibold text-sm mb-2">MITRE ATT&CK Techniques</h4>
                <div className="space-y-1 text-xs">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-600"></div>
                    <span>Initial Access</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-orange-600"></div>
                    <span>Execution</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-amber-600"></div>
                    <span>Persistence</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-blue-600"></div>
                    <span>Lateral Movement</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-purple-600"></div>
                    <span>Exfiltration</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Select an attack path to visualize the attack sequence</p>
            </div>
          )}
          
          {/* Current Step Details */}
          {selectedPath && selectedPath.steps && currentStep < selectedPath.steps.length && (
            <div className="bg-gray-50 p-4 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-semibold">Current Step: {selectedPath.steps[currentStep].title}</h4>
                <Badge 
                  variant={selectedPath.steps[currentStep].riskScore >= 7 ? 'destructive' : 'secondary'}
                >
                  Risk: {selectedPath.steps[currentStep].riskScore}/10
                </Badge>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <strong>Technique:</strong> {selectedPath.steps[currentStep].technique}
                </div>
                <div>
                  <strong>Vector:</strong> {selectedPath.steps[currentStep].vector}
                </div>
                <div className="md:col-span-2">
                  <strong>Description:</strong> {selectedPath.steps[currentStep].description}
                </div>
                
                {selectedPath.steps[currentStep].mitigations && (
                  <div className="md:col-span-2">
                    <strong>Mitigations:</strong>
                    <ul className="list-disc list-inside mt-1 space-y-1">
                      {selectedPath.steps[currentStep].mitigations.map((mitigation, index) => (
                        <li key={index} className="text-sm text-gray-600">{mitigation}</li>
                      ))}
                    </ul>
                  </div>
                )}
                
                {selectedPath.steps[currentStep].affectedAssets && (
                  <div className="md:col-span-2">
                    <strong>Affected Assets:</strong>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedPath.steps[currentStep].affectedAssets.map((asset, index) => (
                        <Badge key={index} variant="outline" className="text-xs">
                          {asset.name || asset.ip}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default AttackPathVisualization;