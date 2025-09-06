import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { ZoomIn, ZoomOut, RotateCcw, Download, Filter, Search } from 'lucide-react';

const NetworkTopologyVisualization = ({ 
  networkData, 
  vulnerabilities = [], 
  onNodeClick, 
  onLinkClick,
  height = 600,
  width = 800,
  showVulnerabilities = true,
  showServices = true,
  filterCriteria = null
}) => {
  const svgRef = useRef();
  const containerRef = useRef();
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedLink, setSelectedLink] = useState(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredData, setFilteredData] = useState(networkData);
  const [simulation, setSimulation] = useState(null);
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, content: '' });

  // Color schemes for different node types
  const nodeColors = {
    host: '#3b82f6',      // Blue
    router: '#10b981',    // Green
    switch: '#f59e0b',    // Amber
    firewall: '#ef4444',  // Red
    server: '#8b5cf6',    // Purple
    database: '#06b6d4',  // Cyan
    unknown: '#6b7280'    // Gray
  };

  // Vulnerability severity colors
  const vulnerabilityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#65a30d',
    info: '#0891b2'
  };

  // Process and filter network data
  useEffect(() => {
    if (!networkData) return;

    let filtered = { ...networkData };

    // Apply search filter
    if (searchTerm) {
      filtered.nodes = networkData.nodes.filter(node => 
        node.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        node.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        node.ip?.toLowerCase().includes(searchTerm.toLowerCase())
      );
      
      const nodeIds = new Set(filtered.nodes.map(n => n.id));
      filtered.links = networkData.links.filter(link => 
        nodeIds.has(link.source) && nodeIds.has(link.target)
      );
    }

    // Apply custom filters
    if (filterCriteria) {
      if (filterCriteria.nodeTypes) {
        filtered.nodes = filtered.nodes.filter(node => 
          filterCriteria.nodeTypes.includes(node.type)
        );
      }
      
      if (filterCriteria.vulnerabilityLevels) {
        filtered.nodes = filtered.nodes.filter(node => {
          const nodeVulns = vulnerabilities.filter(v => v.host === node.ip);
          return nodeVulns.some(v => filterCriteria.vulnerabilityLevels.includes(v.severity));
        });
      }
    }

    setFilteredData(filtered);
  }, [networkData, searchTerm, filterCriteria, vulnerabilities]);

  // Initialize D3 visualization
  useEffect(() => {
    if (!filteredData || !filteredData.nodes || !filteredData.links) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Set up dimensions
    const margin = { top: 20, right: 20, bottom: 20, left: 20 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Create main group
    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Set up zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.1, 10])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setZoomLevel(event.transform.k);
      });

    svg.call(zoom);

    // Create force simulation
    const sim = d3.forceSimulation(filteredData.nodes)
      .force('link', d3.forceLink(filteredData.links)
        .id(d => d.id)
        .distance(d => {
          // Adjust link distance based on connection type
          switch (d.type) {
            case 'direct': return 100;
            case 'routed': return 150;
            case 'vpn': return 200;
            default: return 120;
          }
        })
      )
      .force('charge', d3.forceManyBody()
        .strength(d => {
          // Adjust repulsion based on node importance
          const vulnCount = vulnerabilities.filter(v => v.host === d.ip).length;
          return -300 - (vulnCount * 50);
        })
      )
      .force('center', d3.forceCenter(innerWidth / 2, innerHeight / 2))
      .force('collision', d3.forceCollide()
        .radius(d => {
          const vulnCount = vulnerabilities.filter(v => v.host === d.ip).length;
          return 20 + (vulnCount * 2);
        })
      );

    setSimulation(sim);

    // Create arrow markers for directed links
    const defs = svg.append('defs');
    
    defs.selectAll('marker')
      .data(['end'])
      .enter().append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#666');

    // Create links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(filteredData.links)
      .enter().append('line')
      .attr('stroke', d => {
        switch (d.type) {
          case 'secure': return '#10b981';
          case 'insecure': return '#ef4444';
          case 'vpn': return '#8b5cf6';
          default: return '#6b7280';
        }
      })
      .attr('stroke-width', d => {
        switch (d.strength || 'normal') {
          case 'strong': return 3;
          case 'weak': return 1;
          default: return 2;
        }
      })
      .attr('stroke-dasharray', d => d.type === 'vpn' ? '5,5' : null)
      .attr('marker-end', 'url(#arrowhead)')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedLink(d);
        if (onLinkClick) onLinkClick(d);
      })
      .on('mouseover', (event, d) => {
        showTooltip(event, `Connection: ${d.source.id} → ${d.target.id}\nType: ${d.type}\nProtocol: ${d.protocol || 'Unknown'}`);
      })
      .on('mouseout', hideTooltip);

    // Create node groups
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(filteredData.nodes)
      .enter().append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended)
      )
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(d);
        if (onNodeClick) onNodeClick(d);
      })
      .on('mouseover', (event, d) => {
        const vulnCount = vulnerabilities.filter(v => v.host === d.ip).length;
        const tooltip = `Host: ${d.hostname || d.id}\nIP: ${d.ip}\nType: ${d.type}\nOS: ${d.os || 'Unknown'}\nVulnerabilities: ${vulnCount}`;
        showTooltip(event, tooltip);
      })
      .on('mouseout', hideTooltip);

    // Add node circles
    node.append('circle')
      .attr('r', d => {
        const vulnCount = vulnerabilities.filter(v => v.host === d.ip).length;
        return Math.max(15, 15 + (vulnCount * 2));
      })
      .attr('fill', d => {
        if (showVulnerabilities) {
          const nodeVulns = vulnerabilities.filter(v => v.host === d.ip);
          if (nodeVulns.length > 0) {
            const maxSeverity = nodeVulns.reduce((max, v) => {
              const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
              return severityOrder[v.severity] > severityOrder[max] ? v.severity : max;
            }, 'info');
            return vulnerabilityColors[maxSeverity];
          }
        }
        return nodeColors[d.type] || nodeColors.unknown;
      })
      .attr('stroke', d => selectedNode?.id === d.id ? '#000' : '#fff')
      .attr('stroke-width', d => selectedNode?.id === d.id ? 3 : 2);

    // Add vulnerability indicators
    if (showVulnerabilities) {
      node.each(function(d) {
        const nodeVulns = vulnerabilities.filter(v => v.host === d.ip);
        if (nodeVulns.length > 0) {
          d3.select(this).append('circle')
            .attr('r', 8)
            .attr('cx', 12)
            .attr('cy', -12)
            .attr('fill', '#dc2626')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
          
          d3.select(this).append('text')
            .attr('x', 12)
            .attr('y', -8)
            .attr('text-anchor', 'middle')
            .attr('fill', '#fff')
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .text(nodeVulns.length > 9 ? '9+' : nodeVulns.length);
        }
      });
    }

    // Add service indicators
    if (showServices) {
      node.each(function(d) {
        if (d.services && d.services.length > 0) {
          const serviceGroup = d3.select(this).append('g')
            .attr('class', 'services');
          
          d.services.slice(0, 3).forEach((service, i) => {
            serviceGroup.append('rect')
              .attr('x', -15 + (i * 10))
              .attr('y', 18)
              .attr('width', 8)
              .attr('height', 8)
              .attr('fill', getServiceColor(service.name))
              .attr('stroke', '#fff')
              .attr('stroke-width', 1);
          });
        }
      });
    }

    // Add node labels
    node.append('text')
      .attr('dy', 35)
      .attr('text-anchor', 'middle')
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .attr('fill', '#374151')
      .text(d => d.hostname || d.id);

    // Add IP labels
    node.append('text')
      .attr('dy', 48)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('fill', '#6b7280')
      .text(d => d.ip);

    // Update positions on simulation tick
    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node
        .attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragstarted(event, d) {
      if (!event.active) sim.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event, d) {
      if (!event.active) sim.alphaTarget(0);
      d.fx = null;
      d.fy = null;
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

    // Service color mapping
    function getServiceColor(serviceName) {
      const serviceColors = {
        'http': '#3b82f6',
        'https': '#10b981',
        'ssh': '#8b5cf6',
        'ftp': '#f59e0b',
        'smtp': '#ef4444',
        'dns': '#06b6d4',
        'mysql': '#ec4899',
        'postgresql': '#14b8a6'
      };
      return serviceColors[serviceName.toLowerCase()] || '#6b7280';
    }

    return () => {
      if (sim) sim.stop();
    };
  }, [filteredData, vulnerabilities, showVulnerabilities, showServices, selectedNode]);

  // Control functions
  const handleZoomIn = useCallback(() => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom().scaleBy, 1.5
    );
  }, []);

  const handleZoomOut = useCallback(() => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom().scaleBy, 0.67
    );
  }, []);

  const handleReset = useCallback(() => {
    const svg = d3.select(svgRef.current);
    svg.transition().call(
      d3.zoom().transform,
      d3.zoomIdentity
    );
    if (simulation) {
      simulation.alpha(1).restart();
    }
  }, [simulation]);

  const handleExport = useCallback(() => {
    const svg = svgRef.current;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'network-topology.svg';
    link.click();
    URL.revokeObjectURL(url);
  }, []);

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            Network Topology
            {filteredData?.nodes && (
              <Badge variant="secondary">
                {filteredData.nodes.length} nodes, {filteredData.links?.length || 0} connections
              </Badge>
            )}
          </CardTitle>
          
          <div className="flex items-center gap-2">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search nodes..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 pr-3 py-2 border rounded-md text-sm w-48"
              />
            </div>
            
            {/* Controls */}
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={handleZoomIn}>
                    <ZoomIn className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom In</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={handleZoomOut}>
                    <ZoomOut className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Zoom Out</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={handleReset}>
                    <RotateCcw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Reset View</TooltipContent>
              </Tooltip>
            </TooltipProvider>
            
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={handleExport}>
                    <Download className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Export SVG</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
        </div>
      </CardHeader>
      
      <CardContent>
        <div ref={containerRef} className="relative">
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
          
          {/* Legend */}
          <div className="absolute top-4 right-4 bg-white p-3 rounded-lg shadow-lg border">
            <h4 className="font-semibold text-sm mb-2">Legend</h4>
            
            <div className="space-y-1 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                <span>Host</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span>Router</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-amber-500"></div>
                <span>Switch</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <span>Firewall</span>
              </div>
              
              {showVulnerabilities && (
                <>
                  <hr className="my-2" />
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-600"></div>
                    <span>Critical Vuln</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-orange-600"></div>
                    <span>High Vuln</span>
                  </div>
                </>
              )}
            </div>
          </div>
          
          {/* Zoom indicator */}
          <div className="absolute bottom-4 left-4 bg-white px-2 py-1 rounded text-xs border">
            Zoom: {Math.round(zoomLevel * 100)}%
          </div>
        </div>
        
        {/* Selected node/link details */}
        {(selectedNode || selectedLink) && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            {selectedNode && (
              <div>
                <h4 className="font-semibold mb-2">Selected Node: {selectedNode.hostname || selectedNode.id}</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <strong>IP Address:</strong> {selectedNode.ip}
                  </div>
                  <div>
                    <strong>Type:</strong> {selectedNode.type}
                  </div>
                  <div>
                    <strong>OS:</strong> {selectedNode.os || 'Unknown'}
                  </div>
                  <div>
                    <strong>Vulnerabilities:</strong> {vulnerabilities.filter(v => v.host === selectedNode.ip).length}
                  </div>
                </div>
                
                {selectedNode.services && selectedNode.services.length > 0 && (
                  <div className="mt-2">
                    <strong>Services:</strong>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedNode.services.map((service, index) => (
                        <Badge key={index} variant="outline" className="text-xs">
                          {service.name}:{service.port}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {selectedLink && (
              <div>
                <h4 className="font-semibold mb-2">Selected Connection</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <strong>Source:</strong> {selectedLink.source.id}
                  </div>
                  <div>
                    <strong>Target:</strong> {selectedLink.target.id}
                  </div>
                  <div>
                    <strong>Type:</strong> {selectedLink.type}
                  </div>
                  <div>
                    <strong>Protocol:</strong> {selectedLink.protocol || 'Unknown'}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default NetworkTopologyVisualization;