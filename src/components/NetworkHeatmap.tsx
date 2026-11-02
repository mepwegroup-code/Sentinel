import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Grid, Shield, AlertTriangle, ShieldAlert, Cpu, Info, RefreshCw, Zap, Activity, Radio, Layers } from 'lucide-react';

interface HeatmapNode {
  ip: string;
  hostIndex: number;
  row: number;
  col: number;
  status: 'active' | 'filtered' | 'inactive';
  rttMs?: number;
  openPortsCount: number;
  vulnerabilityCount: number;
  criticalCount: number;
  densityScore: number; // calculated combined risk density
  osGuess: string;
  detectedServices: string[];
}

interface NetworkHeatmapProps {
  targetDomain?: string;
  openPortsCount?: number;
  theme?: string;
}

export const NetworkHeatmap: React.FC<NetworkHeatmapProps> = ({
  targetDomain = 'scanme.nmap.org',
  openPortsCount = 3,
  theme
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [nodes, setNodes] = useState<HeatmapNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<HeatmapNode | null>(null);
  const [subnetPrefix, setSubnetPrefix] = useState('192.168.1');
  const [mode, setMode] = useState<'ports' | 'hosts'>('ports');
  const [isLoading, setIsLoading] = useState(false);
  const [measuredAt, setMeasuredAt] = useState<string>('');

  // Actively measure real socket telemetry from backend API
  const fetchLiveMeasurements = async (target: string, probeMode: 'ports' | 'hosts', prefix: string) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/measure-target-heatmap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target || 'scanme.nmap.org',
          mode: probeMode,
          subnetPrefix: prefix
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (Array.isArray(data.nodes)) {
          setNodes(data.nodes);
          setMeasuredAt(data.measuredAt || new Date().toISOString());
        }
      }
    } catch (err) {
      console.error("Failed to load real measured heatmap:", err);
    } finally {
      setIsLoading(false);
    }
  };

  // Initial load and on targetDomain / mode change
  useEffect(() => {
    fetchLiveMeasurements(targetDomain, mode, subnetPrefix);
  }, [targetDomain, mode, subnetPrefix]);

  // Handle Refresh / Trigger fresh socket probe
  const handleRegenerate = () => {
    fetchLiveMeasurements(targetDomain, mode, subnetPrefix);
  };

  // D3 Render Loop
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || nodes.length === 0) return;

    const container = containerRef.current;
    const width = container.clientWidth || 600;
    const height = Math.min(width * 0.75, 420);
    const margin = { top: 20, right: 20, bottom: 40, left: 40 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('style', 'max-width: 100%; height: auto;');

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    // Grid details
    const cols = 8;
    const rows = 8;
    const cellWidth = innerWidth / cols;
    const cellHeight = innerHeight / rows;

    const isCyberpunk = document.documentElement.classList.contains('cyberpunk');

    // Color scale for risk density score (safe is green, then yellows, oranges, deep reds for high risk)
    const colorScale = d3.scaleSequential<string>()
      .domain([0, 15]) // max estimated density score is around 15
      .interpolator((t) => {
        if (isCyberpunk) {
          if (t === 0) return '#060a14'; // Inactive/Offline (Deep black)
          if (t < 0.15) return '#0d1829'; // Filtered / Low response
          if (t < 0.4) return '#06302b'; // Active, Low Risk (Cyber Emerald tint)
          if (t < 0.7) return '#3a2704'; // Moderate Risk (Cyber Amber/Orange tint)
          return '#40031c'; // High/Critical Risk (Cyber Hot pink/red tint)
        }
        // Custom interpolator matching our sophisticated light scheme
        if (t === 0) return '#f1f5f9'; // Inactive/Offline (Cool Gray)
        if (t < 0.15) return '#e2e8f0'; // Filtered / Low response
        if (t < 0.4) return '#fef3c7'; // Active, Low Risk (Light amber)
        if (t < 0.7) return '#fed7aa'; // Moderate Risk (Orange tint)
        return '#fee2e2'; // High/Critical Risk (Red tint)
      });

    // Outer border stroke color scale for high risks
    const strokeScale = (d: HeatmapNode) => {
      if (isCyberpunk) {
        if (d.criticalCount > 0) return '#ff0055'; // Solid Neon Pink for critical hosts
        if (d.vulnerabilityCount > 0) return '#ffea00'; // Solid Neon Yellow
        if (d.status === 'filtered') return '#00ffcc'; // Neon Cyan
        if (d.status === 'active') return '#00ff66'; // Neon green
        return 'transparent';
      }
      if (d.criticalCount > 0) return '#dc2626'; // Solid Red for critical hosts
      if (d.vulnerabilityCount > 0) return '#ea580c'; // Solid Orange
      if (d.status === 'filtered') return '#cbd5e1';
      if (d.status === 'active') return '#2563eb'; // Blue border
      return 'transparent';
    };

    // Render cells
    const cells = g.selectAll('.cell')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'cell cursor-pointer')
      .attr('transform', d => `translate(${d.col * cellWidth}, ${d.row * cellHeight})`);

    // Draw cell rectangles
    cells.append('rect')
      .attr('width', cellWidth - 4)
      .attr('height', cellHeight - 4)
      .attr('rx', 4)
      .attr('fill', d => colorScale(d.densityScore))
      .attr('stroke', d => strokeScale(d))
      .attr('stroke-width', d => d.criticalCount > 0 ? 2 : 1)
      .on('mouseenter', (_event, d) => {
        setSelectedNode(d);
      })
      .on('click', (_event, d) => {
        setSelectedNode(d);
      });

    // Label each cell with port or host index identifier
    cells.append('text')
      .attr('x', cellWidth / 2 - 2)
      .attr('y', cellHeight / 2 + 3)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .attr('fill', d => {
        if (isCyberpunk) {
          if (d.densityScore > 8) return '#ff0055';
          if (d.densityScore > 3) return '#ffea00';
          if (d.status === 'active') return '#00ff66';
          return '#475569';
        }
        if (d.densityScore > 8) return '#991b1b';
        if (d.densityScore > 3) return '#c2410c';
        if (d.status === 'inactive') return '#94a3b8';
        return '#334155';
      })
      .text(d => mode === 'ports' ? `:${d.hostIndex}` : `.${d.hostIndex}`);

    // Add tiny indicator dots inside cells with critical vulns
    cells.filter(d => d.criticalCount > 0)
      .append('circle')
      .attr('cx', cellWidth - 10)
      .attr('cy', 8)
      .attr('r', 3.5)
      .attr('fill', isCyberpunk ? '#ff0055' : '#ef4444');

    // Axes Labels
    // X Axis Labels (Columns 0-7)
    const xLabels = d3.range(cols);
    g.selectAll('.x-label')
      .data(xLabels)
      .enter()
      .append('text')
      .attr('x', d => d * cellWidth + cellWidth / 2 - 2)
      .attr('y', innerHeight + 18)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('fill', isCyberpunk ? '#00f0ff' : '#64748b')
      .text(d => `C${d}`);

    // Y Axis Labels (Rows 0-7)
    const yLabels = d3.range(rows);
    g.selectAll('.y-label')
      .data(yLabels)
      .enter()
      .append('text')
      .attr('x', -10)
      .attr('y', d => d * cellHeight + cellHeight / 2 + 3)
      .attr('text-anchor', 'end')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('fill', isCyberpunk ? '#00f0ff' : '#64748b')
      .text(d => `R${d}`);

  }, [nodes, theme, mode]);

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <Grid className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              D3.js Real Measured Penetration & Vulnerability Heatmap
            </h3>
            <span className="text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded font-mono font-bold flex items-center gap-1">
              <Activity className="w-3 h-3 text-emerald-600 animate-pulse" />
              Live Socket Measurements
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            {mode === 'ports' 
              ? `Real TCP socket latency & exposure matrix for target `
              : `64-Host Subnet live reachability for `}
            <span className="font-mono text-slate-700 font-bold">{mode === 'ports' ? targetDomain : `${subnetPrefix}.0/24`}</span>
            {measuredAt && (
              <span className="text-slate-400 text-[10px] ml-2 font-mono">
                (Sampled: {new Date(measuredAt).toLocaleTimeString()})
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="bg-slate-100 p-0.5 rounded-lg border border-slate-200 flex items-center text-[11px]">
            <button
              onClick={() => setMode('ports')}
              className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                mode === 'ports' 
                  ? 'bg-white text-indigo-700 shadow-2xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              64-Port Matrix
            </button>
            <button
              onClick={() => setMode('hosts')}
              className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                mode === 'hosts' 
                  ? 'bg-white text-indigo-700 shadow-2xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Subnet Hosts (/24)
            </button>
          </div>

          <button
            onClick={handleRegenerate}
            disabled={isLoading}
            className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 border border-slate-200 rounded-md text-[11px] font-semibold flex items-center gap-1 cursor-pointer transition-colors"
            title="Trigger fresh live TCP socket probe"
          >
            <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin text-blue-600' : ''}`} />
            <span>Re-Probe</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left 7 Cols: Interactive SVG Map */}
        <div ref={containerRef} className="lg:col-span-7 bg-slate-50/50 rounded-lg p-2 border border-slate-100 relative">
          <svg ref={svgRef} className="w-full" />

          {/* Map Color Legend */}
          <div className="flex flex-wrap items-center gap-3 mt-1.5 pt-2 border-t border-slate-200/60 text-[10px] text-slate-500 font-mono">
            <span className="font-bold uppercase tracking-wider text-[9px]">Legend:</span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-xs bg-[#f1f5f9] border border-slate-300 block" />
              Closed / Inactive
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-xs bg-[#e2e8f0] border border-slate-300 block" />
              Filtered (Timeout)
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-xs bg-[#fef3c7] border border-[#2563eb] block" />
              Open / Safe
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-xs bg-[#fed7aa] border border-[#ea580c] block" />
              Mod. Risk
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-xs bg-[#fee2e2] border border-[#dc2626] block" />
              Critical / Backdoor
            </span>
          </div>
        </div>

        {/* Right 5 Cols: Host Spec / Inspector */}
        <div className="lg:col-span-5 flex flex-col justify-between p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3 min-h-[300px]">
          {selectedNode ? (
            <div className="space-y-3.5 text-xs animate-in fade-in duration-200">
              <div className="border-b border-slate-200 pb-2.5">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-mono text-xs font-bold text-slate-800 bg-white border border-slate-200 px-2 py-0.5 rounded shadow-2xs">
                    {selectedNode.ip}
                  </span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
                    selectedNode.status === 'active' ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' :
                    selectedNode.status === 'filtered' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                    'bg-slate-200 text-slate-600'
                  }`}>
                    {selectedNode.status.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mt-1">
                  <span>Target: {mode === 'ports' ? `Port ${selectedNode.hostIndex}/TCP` : `Host ID: offset_${selectedNode.hostIndex}`}</span>
                  {selectedNode.rttMs !== undefined && (
                    <span className="text-indigo-600 font-bold font-mono">Measured RTT: {selectedNode.rttMs} ms</span>
                  )}
                </div>
              </div>

              {selectedNode.status !== 'inactive' ? (
                <div className="space-y-3">
                  {/* System & OS Specs */}
                  <div className="grid grid-cols-2 gap-2 bg-white p-2.5 rounded-lg border border-slate-100">
                    <div>
                      <span className="text-[9px] uppercase font-mono text-slate-400 block">Service / Fingerprint</span>
                      <strong className="text-slate-800 font-sans">{selectedNode.osGuess}</strong>
                    </div>
                    <div>
                      <span className="text-[9px] uppercase font-mono text-slate-400 block">Socket State</span>
                      <strong className="text-slate-800 font-mono">{selectedNode.openPortsCount > 0 ? '1 Open TCP Socket' : 'Filtered / Dropped'}</strong>
                    </div>
                  </div>

                  {/* Vulnerability Counts */}
                  <div className="space-y-1.5">
                    <span className="text-[9px] uppercase font-bold tracking-wider text-slate-500 block">Security Assessment</span>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2 bg-amber-50 border border-amber-100 rounded-lg flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                        <div>
                          <span className="text-[9px] text-amber-700 block font-bold leading-none">Medium Risk</span>
                          <span className="font-mono font-bold text-amber-900">{selectedNode.vulnerabilityCount} Vulns</span>
                        </div>
                      </div>

                      <div className="p-2 bg-red-50 border border-red-100 rounded-lg flex items-center gap-2">
                        <ShieldAlert className="w-3.5 h-3.5 text-red-600 shrink-0" />
                        <div>
                          <span className="text-[9px] text-red-700 block font-bold leading-none">Critical Risk</span>
                          <span className="font-mono font-bold text-red-900">{selectedNode.criticalCount} Vulns</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Services List */}
                  <div>
                    <span className="text-[9px] uppercase font-mono text-slate-400 block mb-1">Active Port Banners / Service</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedNode.detectedServices && selectedNode.detectedServices.length > 0 ? (
                        selectedNode.detectedServices.map((srv, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-blue-50 text-blue-800 border border-blue-100 rounded font-mono text-[9px]">
                            {srv}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-400 italic text-[10px]">No active service banner</span>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-slate-400 italic text-[11px] bg-white rounded-lg border border-slate-100">
                  Target socket is closed (TCP RST returned or ICMP unreachable).
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center text-center py-12 text-slate-400 space-y-2 flex-1">
              <Zap className="w-6 h-6 text-indigo-400" />
              <div>
                <h4 className="text-xs font-bold text-slate-700 uppercase">Live Matrix Inspector</h4>
                <p className="text-[10px] text-slate-400 mt-0.5 max-w-[200px]">Hover or click any cell in the 8x8 matrix to view measured socket RTT and service banner details.</p>
              </div>
            </div>
          )}

          {/* Quick Informational Tip */}
          <div className="p-2.5 bg-indigo-50/50 border border-indigo-100 rounded-lg flex items-start gap-1.5 text-[10px] text-indigo-950 font-mono">
            <Info className="w-3.5 h-3.5 text-indigo-600 shrink-0 mt-0.5" />
            <p className="leading-normal">
              Measured in real time via native TCP socket handshakes. Color density corresponds directly to calculated risk exposure and measured RTT.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
