import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { 
  Network, 
  RefreshCw, 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  Maximize2, 
  Flame, 
  Server, 
  Laptop, 
  Smartphone, 
  Tv, 
  Pause, 
  Play, 
  Zap,
  ZoomIn,
  ZoomOut
} from 'lucide-react';
import { LanDevice } from '../types';

export interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  ip: string;
  mac?: string;
  type: 'main' | 'gateway' | 'workstation' | 'mobile' | 'iot' | 'suspicious' | 'rogue' | 'cloud';
  riskLevel: 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
  isRogue: boolean;
  status: 'online' | 'offline' | 'unresponsive';
  vendor?: string;
  openPorts?: number[];
  trafficRateKbps: number;
  packetsPerSec: number;
  protocol: 'TCP' | 'UDP' | 'TLS' | 'ICMP' | 'DNS' | 'HTTP';
  radius: number;
}

export interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  id: string;
  source: string | GraphNode;
  target: string | GraphNode;
  trafficRateKbps: number;
  packetFlow: 'inbound' | 'outbound' | 'bidirectional';
  protocol: string;
  isThreat: boolean;
  active: boolean;
}

interface NetworkForceGraphProps {
  devices?: LanDevice[];
  onSelectNode?: (node: GraphNode | null) => void;
}

export const NetworkForceGraph: React.FC<NetworkForceGraphProps> = ({ devices, onSelectNode }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isLiveActive, setIsLiveActive] = useState<boolean>(true);
  const [totalTrafficKbps, setTotalTrafficKbps] = useState<number>(1420);
  const [packetCount, setPacketCount] = useState<number>(8450);
  const [threatCount, setThreatCount] = useState<number>(0);

  // Simulation ref so we can update or manipulate it
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const graphDataRef = useRef<{ nodes: GraphNode[]; links: GraphLink[] }>({ nodes: [], links: [] });

  // Initialize and update data whenever devices changes
  useEffect(() => {
    // Construct default graph nodes & links
    const nodes: GraphNode[] = [
      {
        id: 'main-machine',
        label: 'Sentinel OS Host (This Machine)',
        ip: '192.168.1.105',
        mac: '3C:22:FB:41:88:E2',
        type: 'main',
        riskLevel: 'Safe',
        isRogue: false,
        status: 'online',
        vendor: 'Workstation Host Node',
        openPorts: [80, 443, 3000],
        trafficRateKbps: 850,
        packetsPerSec: 120,
        protocol: 'TCP',
        radius: 26,
      },
      {
        id: 'gateway-router',
        label: 'Default Gateway (Router)',
        ip: '192.168.1.1',
        mac: 'D8:0D:17:A2:3C:99',
        type: 'gateway',
        riskLevel: 'Low',
        isRogue: false,
        status: 'online',
        vendor: 'TP-Link / FiberHome Modem',
        openPorts: [80, 443, 53],
        trafficRateKbps: 620,
        packetsPerSec: 95,
        protocol: 'DNS',
        radius: 22,
      },
      {
        id: 'wan-cloud',
        label: 'External WAN / Internet Uplink',
        ip: '113.161.72.10 (Public)',
        type: 'cloud',
        riskLevel: 'Safe',
        isRogue: false,
        status: 'online',
        vendor: 'ISP Backbone Gateway',
        trafficRateKbps: 1200,
        packetsPerSec: 180,
        protocol: 'TLS',
        radius: 20,
      }
    ];

    // If external LAN devices are provided or we map custom ones
    const externalDevices: LanDevice[] = devices && devices.length > 0 ? devices : [
      {
        ip: '192.168.1.25',
        mac: 'AC:BC:32:B1:09:44',
        vendor: 'Apple iPhone 15 Pro',
        hostname: 'user-mobile.lan',
        deviceType: 'Mobile Phone',
        status: 'online',
        openPorts: [],
        riskLevel: 'Safe',
        isRogue: false,
        anomalyIndicators: [],
        responseLatencyMs: 14
      },
      {
        ip: '192.168.1.50',
        mac: '98:0D:2E:7C:12:AA',
        vendor: 'Samsung Tizen Smart TV',
        hostname: 'livingroom-tv.lan',
        deviceType: 'IoT / Smart Device',
        status: 'online',
        openPorts: [8001, 8080],
        riskLevel: 'Low',
        isRogue: false,
        anomalyIndicators: ['UPnP Discovery active'],
        responseLatencyMs: 22
      },
      {
        ip: '192.168.1.188',
        mac: 'B8:27:EB:55:78:1C',
        vendor: 'Raspberry Pi / Kali Node',
        hostname: 'kali-audit-node.lan',
        deviceType: 'Suspicious Device',
        status: 'online',
        openPorts: [22, 4444, 8888],
        riskLevel: 'High',
        isRogue: true,
        anomalyIndicators: ['Metasploit payload port 4444 open', 'Aggressive ARP sweeping'],
        responseLatencyMs: 6
      },
      {
        ip: '192.168.1.210',
        mac: '00:0C:29:FE:41:09',
        vendor: 'VMware Virtual Adapter',
        hostname: 'unknown-sniffer.local',
        deviceType: 'Rogue Intruder',
        status: 'online',
        openPorts: [23, 31337],
        riskLevel: 'Critical',
        isRogue: true,
        anomalyIndicators: ['Promiscuous mode sniffing detected', 'Backdoor port 31337'],
        responseLatencyMs: 4
      }
    ];

    externalDevices.forEach((dev, idx) => {
      // Avoid re-adding gateway or self if matching IP
      if (dev.ip === '192.168.1.1' || dev.ip === '192.168.1.105') return;

      let mappedType: GraphNode['type'] = 'workstation';
      if (dev.deviceType === 'Mobile Phone') mappedType = 'mobile';
      else if (dev.deviceType === 'IoT / Smart Device') mappedType = 'iot';
      else if (dev.isRogue || dev.riskLevel === 'Critical') mappedType = 'rogue';
      else if (dev.riskLevel === 'High') mappedType = 'suspicious';

      nodes.push({
        id: `device-${dev.ip}`,
        label: dev.hostname || dev.vendor || dev.ip,
        ip: dev.ip,
        mac: dev.mac,
        type: mappedType,
        riskLevel: dev.riskLevel,
        isRogue: dev.isRogue,
        status: dev.status,
        vendor: dev.vendor,
        openPorts: dev.openPorts,
        trafficRateKbps: dev.isRogue ? 480 : Math.floor(Math.random() * 250) + 30,
        packetsPerSec: dev.isRogue ? 75 : Math.floor(Math.random() * 40) + 5,
        protocol: dev.isRogue ? (dev.openPorts.includes(4444) ? 'TCP' : 'UDP') : 'HTTP',
        radius: dev.isRogue ? 19 : 15,
      });
    });

    // Generate active links between nodes
    const links: GraphLink[] = [
      {
        id: 'link-main-gateway',
        source: 'main-machine',
        target: 'gateway-router',
        trafficRateKbps: 620,
        packetFlow: 'bidirectional',
        protocol: 'Ethernet/TCP',
        isThreat: false,
        active: true
      },
      {
        id: 'link-gateway-cloud',
        source: 'gateway-router',
        target: 'wan-cloud',
        trafficRateKbps: 980,
        packetFlow: 'bidirectional',
        protocol: 'WAN/TLS',
        isThreat: false,
        active: true
      }
    ];

    // Connect external devices to gateway or directly attempting probing of main-machine
    nodes.forEach(n => {
      if (n.id !== 'main-machine' && n.id !== 'gateway-router' && n.id !== 'wan-cloud') {
        // Safe devices route through gateway
        links.push({
          id: `link-gw-${n.id}`,
          source: 'gateway-router',
          target: n.id,
          trafficRateKbps: n.trafficRateKbps,
          packetFlow: 'bidirectional',
          protocol: n.protocol,
          isThreat: n.isRogue,
          active: true
        });

        // If rogue/suspicious, also show direct unauthorized probe link to main-machine
        if (n.isRogue) {
          links.push({
            id: `threat-probe-${n.id}`,
            source: n.id,
            target: 'main-machine',
            trafficRateKbps: 340,
            packetFlow: 'inbound',
            protocol: 'ARP/TCP Probe',
            isThreat: true,
            active: true
          });
        }
      }
    });

    graphDataRef.current = { nodes, links };
    const threatNodesCount = nodes.filter(n => n.isRogue).length;
    setThreatCount(threatNodesCount);

    renderD3Graph();
  }, [devices]);

  // Main D3 force-directed graph renderer
  const renderD3Graph = () => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const width = container.clientWidth || 800;
    const height = 480;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove(); // Clean previous render

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Definitions for glow filters, gradients & arrow markers
    const defs = svg.append('defs');

    // Arrow markers
    defs.append('marker')
      .attr('id', 'arrow-normal')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#64748b');

    defs.append('marker')
      .attr('id', 'arrow-threat')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#ef4444');

    defs.append('marker')
      .attr('id', 'arrow-main')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 24)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#3b82f6');

    // Glow filter for threat nodes
    const threatFilter = defs.append('filter')
      .attr('id', 'threat-glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    threatFilter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');
    const threatMerge = threatFilter.append('feMerge');
    threatMerge.append('feMergeNode').attr('in', 'coloredBlur');
    threatMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Main grouping element with zoom support
    const g = svg.append('g').attr('class', 'main-graph-group');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 3])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Prepare copies of data for d3 simulation mutation
    const nodes: GraphNode[] = graphDataRef.current.nodes.map(d => ({ ...d }));
    const links: GraphLink[] = graphDataRef.current.links.map(d => ({ ...d }));

    // Create D3 Force Simulation
    const simulation = d3.forceSimulation<GraphNode, GraphLink>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links).id(d => d.id).distance(d => {
        if ((d.source as GraphNode).id === 'main-machine' && (d.target as GraphNode).id === 'gateway-router') return 120;
        if ((d.source as GraphNode).id === 'gateway-router' && (d.target as GraphNode).id === 'wan-cloud') return 130;
        return (d as any).isThreat ? 140 : 110;
      }).strength(0.7))
      .force('charge', d3.forceManyBody().strength(d => (d as GraphNode).id === 'main-machine' ? -500 : -280))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => (d as GraphNode).radius + 28));

    simulationRef.current = simulation;

    // Background grid / radar circular rings
    const radarGroup = g.append('g').attr('class', 'radar-rings').attr('opacity', 0.15);
    [80, 160, 240, 320].forEach(r => {
      radarGroup.append('circle')
        .attr('cx', width / 2)
        .attr('cy', height / 2)
        .attr('r', r)
        .attr('fill', 'none')
        .attr('stroke', '#0284c7')
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '4 4');
    });

    // 1. Draw Links (Traffic Channels)
    const linkGroup = g.append('g').attr('class', 'links');
    const linkLines = linkGroup.selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', d => d.isThreat ? '#ef4444' : '#94a3b8')
      .attr('stroke-width', d => d.isThreat ? 2.5 : Math.max(1.5, Math.min(d.trafficRateKbps / 200, 4)))
      .attr('stroke-dasharray', d => d.isThreat ? '6 3' : 'none')
      .attr('stroke-opacity', 0.65)
      .attr('marker-end', d => d.isThreat ? 'url(#arrow-threat)' : 'url(#arrow-normal)');

    // 2. Animated Traffic Particles (Packets flowing along the active links)
    const particleGroup = g.append('g').attr('class', 'traffic-particles');

    // Create particle pools for active links
    const particlesData: { linkId: string; index: number; progress: number; speed: number; isThreat: boolean }[] = [];
    links.forEach(link => {
      const pCount = link.isThreat ? 3 : Math.max(1, Math.min(Math.floor(link.trafficRateKbps / 250), 3));
      for (let i = 0; i < pCount; i++) {
        particlesData.push({
          linkId: link.id,
          index: i,
          progress: (i / pCount) + (Math.random() * 0.2),
          speed: (0.006 + (link.trafficRateKbps / 120000)) * (link.isThreat ? 1.4 : 1.0),
          isThreat: link.isThreat
        });
      }
    });

    const particles = particleGroup.selectAll('circle')
      .data(particlesData)
      .join('circle')
      .attr('r', d => d.isThreat ? 3.5 : 2.5)
      .attr('fill', d => d.isThreat ? '#f43f5e' : '#38bdf8')
      .attr('filter', d => d.isThreat ? 'url(#threat-glow)' : 'none');

    // 3. Draw Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const nodeContainers = nodeGroup.selectAll('g')
      .data(nodes)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(
        d3.drag<SVGGElement, GraphNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node Outer Ring (Pulsing ring for Main & Threat nodes)
    nodeContainers.append('circle')
      .attr('r', d => d.radius + 6)
      .attr('fill', 'none')
      .attr('stroke', d => {
        if (d.type === 'main') return '#3b82f6';
        if (d.isRogue) return '#ef4444';
        if (d.type === 'gateway') return '#6366f1';
        return '#cbd5e1';
      })
      .attr('stroke-width', d => d.type === 'main' || d.isRogue ? 2 : 1)
      .attr('stroke-dasharray', d => d.isRogue ? '4 3' : 'none')
      .attr('opacity', 0.85);

    // Node Primary Circle Fill
    nodeContainers.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => {
        if (d.type === 'main') return '#2563eb';
        if (d.isRogue) return '#dc2626';
        if (d.type === 'gateway') return '#4f46e5';
        if (d.type === 'cloud') return '#0284c7';
        if (d.type === 'suspicious') return '#ea580c';
        if (d.type === 'iot') return '#d97706';
        if (d.type === 'mobile') return '#10b981';
        return '#475569';
      })
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 2.5)
      .attr('filter', d => d.isRogue ? 'url(#threat-glow)' : 'none')
      .attr('class', 'node-circle');

    // Status Ping Indicator for Online/Active
    nodeContainers.append('circle')
      .attr('cx', d => d.radius * 0.7)
      .attr('cy', d => -d.radius * 0.7)
      .attr('r', 4)
      .attr('fill', d => d.isRogue ? '#ef4444' : '#10b981')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 1.2);

    // Node Text Labels
    const labels = nodeContainers.append('text')
      .text(d => d.ip)
      .attr('y', d => d.radius + 14)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .attr('fill', d => d.isRogue ? '#dc2626' : '#1e293b');

    nodeContainers.append('text')
      .text(d => d.type === 'main' ? '★ Sentinel Host' : (d.label.length > 18 ? d.label.substring(0, 16) + '…' : d.label))
      .attr('y', d => d.radius + 25)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('fill', '#64748b');

    // Click handler for node inspection
    nodeContainers.on('click', (event, d) => {
      setSelectedNode(d);
      if (onSelectNode) onSelectNode(d);
      
      // Visual selection highlight
      nodeContainers.selectAll('.node-circle')
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 2.5);

      d3.select(event.currentTarget).select('.node-circle')
        .attr('stroke', '#f59e0b')
        .attr('stroke-width', 4);
    });

    // Tick Animation Loop
    simulation.on('tick', () => {
      linkLines
        .attr('x1', d => (d.source as GraphNode).x!)
        .attr('y1', d => (d.source as GraphNode).y!)
        .attr('x2', d => (d.target as GraphNode).x!)
        .attr('y2', d => (d.target as GraphNode).y!);

      nodeContainers.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Particle flow loop using requestAnimationFrame
    let animationFrameId: number;
    const linkMap = new Map(links.map(l => [l.id, l]));

    const animateParticles = () => {
      particlesData.forEach((p, idx) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;

        const currentLink = linkMap.get(p.linkId);
        if (currentLink && currentLink.source && currentLink.target) {
          const s = currentLink.source as GraphNode;
          const t = currentLink.target as GraphNode;
          if (s.x !== undefined && s.y !== undefined && t.x !== undefined && t.y !== undefined) {
            const px = s.x + (t.x - s.x) * p.progress;
            const py = s.y + (t.y - s.y) * p.progress;
            d3.select(particles.nodes()[idx])
              .attr('cx', px)
              .attr('cy', py);
          }
        }
      });

      animationFrameId = requestAnimationFrame(animateParticles);
    };

    animationFrameId = requestAnimationFrame(animateParticles);

    return () => {
      simulation.stop();
      cancelAnimationFrame(animationFrameId);
    };
  };

  // Resize handler with ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(() => {
      renderD3Graph();
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Periodic traffic simulator for live dynamics
  useEffect(() => {
    if (!isLiveActive) return;
    const interval = setInterval(() => {
      setTotalTrafficKbps(prev => {
        const delta = Math.floor(Math.random() * 80) - 35;
        return Math.max(900, prev + delta);
      });
      setPacketCount(prev => prev + Math.floor(Math.random() * 45) + 15);
    }, 1200);

    return () => clearInterval(interval);
  }, [isLiveActive]);

  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().call(zoomBehaviorRef.current.scaleBy, 1.3);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().call(zoomBehaviorRef.current.scaleBy, 0.7);
    }
  };

  const handleResetZoom = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    }
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col">
      {/* Header Controls Bar */}
      <div className="px-6 py-4 border-b border-slate-100 flex flex-wrap items-center justify-between gap-3 bg-slate-50/70">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-xs">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-black text-slate-800 uppercase tracking-tight">
                Live Force-Directed Network Topology Graph
              </h3>
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                D3.js ENGINE ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-slate-500">
              Interactive physics-based graph showing real-time traffic links between the host, gateway, and external detected nodes.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-white border border-slate-200 rounded-xl text-xs font-semibold text-slate-600">
            <Activity className="w-3.5 h-3.5 text-blue-600" />
            <span>Traffic: <strong className="text-slate-800 font-mono">{totalTrafficKbps} Kbps</strong></span>
            <span className="text-slate-300">|</span>
            <span>Packets: <strong className="text-slate-800 font-mono">{packetCount}</strong></span>
          </div>

          <button
            onClick={() => setIsLiveActive(!isLiveActive)}
            className={`p-2 rounded-xl border text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer ${
              isLiveActive 
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100' 
                : 'bg-slate-100 text-slate-600 border-slate-200 hover:bg-slate-200'
            }`}
            title={isLiveActive ? 'Pause packet simulation' : 'Resume simulation'}
          >
            {isLiveActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>

          <div className="flex items-center border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <button 
              onClick={handleZoomIn} 
              className="p-2 hover:bg-slate-100 text-slate-600 transition-colors cursor-pointer"
              title="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={handleZoomOut} 
              className="p-2 hover:bg-slate-100 text-slate-600 transition-colors cursor-pointer border-l border-slate-100"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={handleResetZoom} 
              className="px-2.5 py-1.5 text-[11px] font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer border-l border-slate-100"
              title="Reset view"
            >
              Reset
            </button>
          </div>

          <button
            onClick={renderD3Graph}
            className="p-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition-colors cursor-pointer"
            title="Re-layout Graph Simulation"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Canvas & Details Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-4 min-h-[480px]">
        {/* D3 Canvas Container */}
        <div 
          ref={containerRef} 
          className="lg:col-span-3 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 relative overflow-hidden flex items-center justify-center select-none"
        >
          {/* Subtle Grid Overlay */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:20px_20px] opacity-40 pointer-events-none"></div>

          {/* Legend Banner on top-left of canvas */}
          <div className="absolute top-4 left-4 z-10 bg-slate-900/80 backdrop-blur-md border border-slate-800 rounded-xl p-3 text-[10px] text-slate-300 space-y-1.5 shadow-lg pointer-events-none">
            <div className="font-bold text-slate-200 uppercase tracking-wider text-[9px] mb-1">Topology Legend</div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-blue-600 border border-white"></span>
              <span>Host Machine (Main)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-indigo-600 border border-white"></span>
              <span>Router Gateway</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-emerald-500 border border-white"></span>
              <span>Trusted Local Device</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-600 border border-white animate-pulse"></span>
              <span className="text-rose-400 font-semibold">Rogue / Suspicious Intruder</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3.5 h-0.5 bg-rose-500"></span>
              <span className="text-rose-400 font-semibold">Active Attack / Probe Stream</span>
            </div>
          </div>

          {/* Quick Threat Alert Indicator in Canvas */}
          {threatCount > 0 && (
            <div className="absolute bottom-4 left-4 z-10 bg-rose-950/80 backdrop-blur-md border border-rose-800/80 text-rose-300 rounded-xl px-3.5 py-2 text-xs flex items-center gap-2 shadow-lg">
              <Flame className="w-4 h-4 text-rose-400 animate-bounce" />
              <span><strong>{threatCount} Suspicious Nodes</strong> detected transmitting unauthorised probes to host!</span>
            </div>
          )}

          {/* Actual SVG Canvas */}
          <svg 
            ref={svgRef} 
            className="w-full h-[480px] cursor-grab active:cursor-grabbing block"
          />
        </div>

        {/* Right Sidebar: Selected Node Real-time Telemetry */}
        <div className="border-t lg:border-t-0 lg:border-l border-slate-200 bg-slate-50 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <span className="text-xs font-bold uppercase text-slate-500">Node Inspector</span>
              {selectedNode ? (
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                  selectedNode.isRogue ? 'bg-rose-100 text-rose-800 border-rose-300' :
                  selectedNode.type === 'main' ? 'bg-blue-100 text-blue-800 border-blue-300' :
                  'bg-emerald-100 text-emerald-800 border-emerald-300'
                }`}>
                  {selectedNode.isRogue ? 'Rogue Node' : selectedNode.type}
                </span>
              ) : (
                <span className="text-[11px] text-slate-400 italic">Click any node</span>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-3 mt-4 text-xs">
                <div>
                  <h4 className="font-bold text-slate-800 text-sm">{selectedNode.label}</h4>
                  <p className="font-mono text-slate-500 text-[11px]">{selectedNode.ip}</p>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-2 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">MAC Address:</span>
                    <span className="font-mono text-slate-700 font-semibold">{selectedNode.mac || 'N/A (Virtual)'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Vendor / OS:</span>
                    <span className="text-slate-700 truncate max-w-[130px] font-medium">{selectedNode.vendor || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Live Traffic Rate:</span>
                    <span className="font-mono font-bold text-indigo-600">{selectedNode.trafficRateKbps} Kbps</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Packet Throughput:</span>
                    <span className="font-mono text-slate-700">{selectedNode.packetsPerSec} pkts/s</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Active Protocol:</span>
                    <span className="font-bold text-slate-800">{selectedNode.protocol}</span>
                  </div>
                  {selectedNode.openPorts && selectedNode.openPorts.length > 0 && (
                    <div className="flex justify-between items-center pt-1 border-t border-slate-100">
                      <span className="text-slate-400">Open Ports:</span>
                      <span className="font-mono font-bold text-rose-600">{selectedNode.openPorts.join(', ')}</span>
                    </div>
                  )}
                </div>

                {selectedNode.isRogue ? (
                  <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-[11px] space-y-1">
                    <strong className="flex items-center gap-1 font-bold">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                      Mối Nguy Cấp Tính:
                    </strong>
                    <p>
                      Node đang gửi các gói tin thăm dò không hợp lệ vào máy tính Sentinel OS. Khuyến nghị chặn MAC hoặc cách ly ngay trên Router.
                    </p>
                  </div>
                ) : (
                  <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-[11px] flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>Lưu lượng mạng nội bộ an toàn và được mã hóa tiêu chuẩn.</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-12 text-center text-slate-400 text-xs flex flex-col items-center justify-center">
                <Network className="w-8 h-8 text-slate-300 mb-2" />
                <p className="font-semibold text-slate-600">No Node Selected</p>
                <p className="text-[11px] text-slate-400 mt-1 max-w-[170px]">
                  Click on any node in the canvas to inspect real-time packets and security alerts.
                </p>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-200 text-[11px] text-slate-500">
            <strong>Drag & Drop:</strong> Click and drag any node to test the physical force equilibrium or reposition nodes.
          </div>
        </div>
      </div>
    </div>
  );
};
