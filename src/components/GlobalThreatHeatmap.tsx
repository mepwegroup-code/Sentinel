import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import {
  Globe,
  Flame,
  ShieldAlert,
  Zap,
  Activity,
  Pause,
  Play,
  RotateCcw,
  Crosshair,
  Filter,
  Info,
  Server,
  ArrowRight,
  TrendingUp,
  Cpu,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  AlertOctagon,
  Radar,
  Radio,
  Layers,
  Sparkles,
  Wifi,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  Sliders,
  Laptop,
  Smartphone,
  Tv,
  Camera,
  ShieldCheck,
  ShieldX,
  X,
  ArrowDownLeft,
  ArrowUpRight,
  Gauge,
  Network,
  ZoomIn,
  ZoomOut,
  Move
} from 'lucide-react';
import { GlobalThreatIntel, GlobalThreatAttack, RegionalHotspot, UserLanThreatNode, InternationalRouteSpeed, NetworkTrafficVolumeTelemetry } from '../types';

// Helper formatters for packet bytes and volumes
function formatBytes(bytes: number, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function formatPackets(count: number) {
  if (!count) return '0 pkts';
  if (count >= 1_000_000_000) return `${(count / 1_000_000_000).toFixed(2)} B pkts`;
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)} M pkts`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)} K pkts`;
  return `${count} pkts`;
}

interface GlobalThreatHeatmapProps {
  theme?: string;
  targetDomain?: string;
  onSelectAttack?: (attack: GlobalThreatAttack) => void;
}

// Low-poly world landmass approximations for fast, lightweight, standalone D3 rendering
const WORLD_CONTINENTS_GEO: [number, number][][] = [
  // North America
  [
    [-168, 65], [-160, 71], [-140, 70], [-125, 69], [-100, 74], [-80, 75], [-60, 60],
    [-55, 50], [-65, 44], [-75, 38], [-80, 25], [-97, 26], [-105, 20], [-85, 15],
    [-77, 8], [-83, 10], [-90, 14], [-105, 22], [-115, 30], [-124, 38], [-125, 48],
    [-132, 54], [-140, 60], [-160, 58], [-168, 65]
  ],
  // South America
  [
    [-77, 8], [-72, 11], [-60, 5], [-50, 0], [-35, -5], [-35, -12], [-40, -22],
    [-50, -32], [-58, -38], [-65, -55], [-75, -50], [-72, -35], [-76, -18],
    [-81, -5], [-77, 8]
  ],
  // Europe
  [
    [-10, 36], [-8, 43], [-1, 46], [2, 51], [8, 55], [10, 60], [25, 71],
    [32, 70], [45, 68], [55, 60], [40, 50], [30, 46], [25, 40], [20, 38],
    [10, 37], [0, 37], [-10, 36]
  ],
  // Africa
  [
    [-17, 32], [-5, 36], [10, 37], [25, 32], [32, 31], [40, 22], [51, 12],
    [45, 0], [40, -10], [35, -25], [30, -33], [20, -35], [17, -25], [12, -10],
    [0, 5], [-15, 10], [-17, 20], [-17, 32]
  ],
  // Asia
  [
    [40, 50], [55, 60], [70, 72], [100, 76], [130, 72], [170, 66], [175, 60],
    [160, 55], [142, 50], [130, 42], [122, 30], [115, 22], [105, 10], [100, 5],
    [92, 18], [80, 8], [72, 20], [60, 25], [50, 30], [35, 32], [40, 50]
  ],
  // Australia & Oceania
  [
    [114, -22], [120, -14], [135, -12], [145, -15], [153, -28], [150, -38],
    [138, -36], [130, -32], [116, -34], [114, -22]
  ],
  // Japan Archipelago
  [
    [130, 32], [133, 34], [140, 36], [142, 42], [145, 44], [142, 40], [138, 36], [130, 32]
  ],
  // United Kingdom
  [
    [-5, 50], [-1, 51], [1, 53], [-2, 58], [-5, 58], [-5, 55], [-6, 52], [-5, 50]
  ]
];

export const GlobalThreatHeatmap: React.FC<GlobalThreatHeatmapProps> = ({
  theme = 'dark',
  targetDomain = 'scanme.nmap.org',
  onSelectAttack
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const lanSvgRef = useRef<SVGSVGElement>(null);
  const wanZoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const lanZoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // Zoom level state
  const [wanZoomLevel, setWanZoomLevel] = useState<number>(1);
  const [lanZoomLevel, setLanZoomLevel] = useState<number>(1);
  const [showSpeedBadges, setShowSpeedBadges] = useState<boolean>(true);

  // Core telemetry state
  const [intelData, setIntelData] = useState<GlobalThreatIntel | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [viewMode, setViewMode] = useState<'wan-radar' | 'lan-heat' | 'routes' | 'hardening'>('wan-radar');
  const [selectedAttack, setSelectedAttack] = useState<GlobalThreatAttack | null>(null);
  const [selectedHotspot, setSelectedHotspot] = useState<RegionalHotspot | null>(null);
  const [selectedLanNode, setSelectedLanNode] = useState<UserLanThreatNode | null>(null);
  const [filterCategory, setFilterCategory] = useState<'all' | 'ddos' | 'exploit' | 'botnet'>('all');
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [aiBriefing, setAiBriefing] = useState<string | null>(null);
  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [lastUpdated, setLastUpdated] = useState<string>('');
  
  // Custom IP Override Modal
  const [isIpModalOpen, setIsIpModalOpen] = useState<boolean>(false);
  const [customIpInput, setCustomIpInput] = useState<string>('');
  const [isolatedNodeIds, setIsolatedNodeIds] = useState<string[]>([]);

  // Interactive CEH v13 Hardening Checklist State
  const [hardeningRules, setHardeningRules] = useState([
    { id: 'upnp', label: 'Vô hiệu hóa Universal Plug and Play (UPnP) trên WAN', desc: 'Ngăn chặn botnet tự mở cổng xuyên NAT vào camera và thiết bị IoT nội bộ', status: true },
    { id: 'wan-ping', label: 'Kích hoạt Stealth Mode (Chặn WAN ICMP Ping)', desc: 'Ẩn modem khỏi các công cụ quét tự động của Shodan và Censys', status: true },
    { id: 'admin-pwd', label: 'Đổi mật khẩu quản trị Modem (Mặc định admin/admin)', desc: 'Triệt tiêu 95% cuộc tấn công vét cạn từ botnet Mirai và Mozi', status: true },
    { id: 'remote-mgmt', label: 'Tắt truy cập quản trị từ xa qua WAN (Ports 80/443/8080)', desc: 'Chỉ cho phép đăng nhập cấu hình router từ dải IP nội bộ LAN', status: true },
    { id: 'spi-firewall', label: 'Bật Stateful Packet Inspection (SPI) & SYN Flood Protection', desc: 'Bảo vệ bảng kết nối NAT không bị nghẽn đơ khi bị dội gói tin DoS', status: false },
    { id: 'iot-vlan', label: 'Tách biệt Wi-Fi Khách (Guest VLAN) riêng cho Camera/Smart TV', desc: 'Cô lập thiết bị thông minh để nếu có bị hack cũng không lây lan sang máy tính', status: false }
  ]);

  // Fetch threat intelligence specific to user network
  const fetchUserThreats = async (overrideIp?: string) => {
    setIsLoading(true);
    try {
      let url = '/api/global-threats';
      if (overrideIp) {
        url += `?clientIp=${encodeURIComponent(overrideIp)}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data: GlobalThreatIntel = await res.json();
        setIntelData(data);
        setLastUpdated(new Date().toLocaleTimeString());
        if (!selectedAttack && data.recentAttacks.length > 0) {
          setSelectedAttack(data.recentAttacks[0]);
        }
        if (!selectedLanNode && data.lanNodes && data.lanNodes.length > 0) {
          // Select highest risk node by default
          const highRisk = [...data.lanNodes].sort((a, b) => b.threatScore - a.threatScore)[0];
          setSelectedLanNode(highRisk);
        }
      }
    } catch (err) {
      console.error('Failed to fetch threat telemetry for user network:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUserThreats();
    const interval = setInterval(() => {
      if (isLiveStreaming) {
        fetchUserThreats();
      }
    }, 12000);
    return () => clearInterval(interval);
  }, [isLiveStreaming]);

  // Filtered attacks based on active category
  const filteredAttacks = useMemo(() => {
    if (!intelData) return [];
    if (filterCategory === 'all') return intelData.recentAttacks;
    return intelData.recentAttacks.filter(a => a.category === filterCategory);
  }, [intelData, filterCategory]);

  // Request AI Threat Briefing specifically for User's Network
  const handleGenerateAiBriefing = async () => {
    if (!intelData) return;
    setIsGeneratingAi(true);
    try {
      const res = await fetch('/api/global-threats/ai-briefing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          selectedAttack: selectedAttack,
          region: intelData.userNetwork?.city || selectedAttack?.target.city,
          targetDomain: targetDomain,
          clientIp: intelData.userNetwork?.clientIp,
          isp: intelData.userNetwork?.isp
        })
      });
      if (res.ok) {
        const data = await res.json();
        setAiBriefing(data.briefing);
      } else {
        setAiBriefing('Không thể kết nối AI Copilot. Vui lòng kiểm tra lại cấu hình server.');
      }
    } catch {
      setAiBriefing('Lỗi mạng khi phân tích thông tin tình báo AI.');
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleApplyCustomIp = (e: React.FormEvent) => {
    e.preventDefault();
    if (customIpInput.trim()) {
      fetchUserThreats(customIpInput.trim());
      setIsIpModalOpen(false);
    }
  };

  const toggleIsolateNode = (nodeId: string) => {
    setIsolatedNodeIds(prev => 
      prev.includes(nodeId) ? prev.filter(id => id !== nodeId) : [...prev, nodeId]
    );
  };

  const toggleHardeningRule = (id: string) => {
    setHardeningRules(prev =>
      prev.map(r => r.id === id ? { ...r, status: !r.status } : r)
    );
  };

  // -------------------------------------------------------------
  // D3 Rendering: VIEW 1 - GLOBAL WAN INBOUND RADAR (Focused on User IP)
  // -------------------------------------------------------------
  useEffect(() => {
    if (viewMode !== 'wan-radar') return;
    if (!svgRef.current || !intelData) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = 940;
    const height = 480;

    const userLat = intelData.userNetwork?.lat || 21.0285;
    const userLng = intelData.userNetwork?.lng || 105.8542;

    // Equirectangular projection centered roughly on the user's meridian
    const projection = d3.geoEquirectangular()
      .scale(150)
      .center([userLng > 60 ? 40 : 0, 15])
      .translate([width / 2, height / 2]);

    const pathGenerator = d3.geoPath().projection(projection);

    // Filter Definitions
    const defs = svg.append('defs');

    // Neon Glow Filter
    const glowFilter = defs.append('filter')
      .attr('id', 'neon-glow')
      .attr('x', '-30%')
      .attr('y', '-30%')
      .attr('width', '160%')
      .attr('height', '160%');

    glowFilter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');

    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // User Perimeter Beacon Radial Gradient
    const userBeaconGrad = defs.append('radialGradient')
      .attr('id', 'user-perimeter-glow')
      .attr('cx', '50%')
      .attr('cy', '50%')
      .attr('r', '50%');
    userBeaconGrad.append('stop').attr('offset', '0%').attr('stop-color', '#10b981').attr('stop-opacity', 0.95);
    userBeaconGrad.append('stop').attr('offset', '40%').attr('stop-color', '#059669').attr('stop-opacity', 0.6);
    userBeaconGrad.append('stop').attr('offset', '100%').attr('stop-color', '#047857').attr('stop-opacity', 0);

    // Threat Hotspot Gradients
    intelData.hotspots.forEach(hotspot => {
      const grad = defs.append('radialGradient')
        .attr('id', `heat-grad-${hotspot.id}`)
        .attr('cx', '50%')
        .attr('cy', '50%')
        .attr('r', '50%');

      const coreColor = hotspot.id === 'hotspot-user-perimeter' 
        ? '#10b981' 
        : hotspot.threatLevel === 'Extreme' ? '#ef4444' : '#f59e0b';
      const edgeColor = hotspot.id === 'hotspot-user-perimeter'
        ? '#047857'
        : hotspot.threatLevel === 'Extreme' ? '#dc2626' : '#d97706';

      grad.append('stop').attr('offset', '0%').attr('stop-color', coreColor).attr('stop-opacity', hotspot.intensity);
      grad.append('stop').attr('offset', '50%').attr('stop-color', edgeColor).attr('stop-opacity', hotspot.intensity * 0.45);
      grad.append('stop').attr('offset', '100%').attr('stop-color', edgeColor).attr('stop-opacity', 0);
    });

    const g = svg.append('g').attr('class', 'map-root-group');

    // D3 Zoom & Pan Behavior (Mouse Wheel & Drag)
    const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.6, 8]) // Zoom from 60% to 800%
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setWanZoomLevel(event.transform.k);
      });

    svg.call(zoomBehavior);
    wanZoomRef.current = zoomBehavior;

    // Restore active zoom transform if already applied
    const existingTransform = d3.zoomTransform(svg.node()!);
    if (existingTransform && (existingTransform.k !== 1 || existingTransform.x !== 0 || existingTransform.y !== 0)) {
      g.attr('transform', existingTransform.toString());
    }

    // Graticule grid lines
    const graticule = d3.geoGraticule().step([30, 30]);
    g.append('path')
      .datum(graticule)
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.6)
      .attr('stroke-dasharray', '2 4')
      .attr('opacity', 0.4);

    // Continents
    const continentsGroup = g.append('g').attr('class', 'continents');
    WORLD_CONTINENTS_GEO.forEach((coords) => {
      const lineGen = d3.line<[number, number]>()
        .x(d => projection([d[0], d[1]])?.[0] || 0)
        .y(d => projection([d[0], d[1]])?.[1] || 0)
        .curve(d3.curveCardinalClosed.tension(0.4));

      const pathData = lineGen(coords);
      if (pathData) {
        continentsGroup.append('path')
          .attr('d', pathData)
          .attr('fill', '#0f172a')
          .attr('stroke', '#334155')
          .attr('stroke-width', 0.8)
          .attr('opacity', 0.85);
      }
    });

    // Bounding Box registry for collision-free label & badge positioning
    interface BBox {
      x: number;
      y: number;
      w: number;
      h: number;
    }

    const occupiedBoxes: BBox[] = [];

    const isColliding = (candidate: BBox, pad = 6): boolean => {
      return occupiedBoxes.some(b => !(
        candidate.x + candidate.w + pad < b.x ||
        b.x + b.w + pad < candidate.x ||
        candidate.y + candidate.h + pad < b.y ||
        b.y + b.h + pad < candidate.y
      ));
    };

    // 1. Register User's Network Exclusion Zone First
    const userPos = projection([userLng, userLat]);
    if (userPos) {
      occupiedBoxes.push({
        x: userPos[0] - 75,
        y: userPos[1] - 42,
        w: 150,
        h: 64
      });
    }

    // Heatmap density fields & Hotspot Labels
    const heatGroup = g.append('g').attr('class', 'heatmap-layer');
    const hotspotLabelsGroup = g.append('g').attr('class', 'hotspot-labels-layer');

    intelData.hotspots.forEach(hotspot => {
      const pos = projection([hotspot.lng, hotspot.lat]);
      if (!pos) return;

      const isUser = hotspot.id === 'hotspot-user-perimeter';
      const baseRadius = isUser ? 50 : 32 + (hotspot.intensity * 35);

      heatGroup.append('circle')
        .attr('cx', pos[0])
        .attr('cy', pos[1])
        .attr('r', baseRadius)
        .attr('fill', `url(#heat-grad-${hotspot.id})`)
        .attr('pointer-events', 'none');

      // Pulsing outer shockwave ring
      heatGroup.append('circle')
        .attr('cx', pos[0])
        .attr('cy', pos[1])
        .attr('r', baseRadius * 0.5)
        .attr('fill', 'none')
        .attr('stroke', isUser ? '#10b981' : hotspot.threatLevel === 'Extreme' ? '#ef4444' : '#f59e0b')
        .attr('stroke-width', isUser ? 1.8 : 1.2)
        .attr('stroke-dasharray', isUser ? '4 2' : '3 3')
        .attr('opacity', 0.85);

      if (!isUser) {
        const anchor = heatGroup.append('g')
          .attr('class', 'hotspot-anchor cursor-pointer')
          .attr('transform', `translate(${pos[0]}, ${pos[1]})`)
          .on('click', () => setSelectedHotspot(hotspot));

        anchor.append('circle')
          .attr('r', 4.5)
          .attr('fill', hotspot.threatLevel === 'Extreme' ? '#ef4444' : '#f59e0b')
          .attr('stroke', '#ffffff')
          .attr('stroke-width', 1.2)
          .attr('filter', 'url(#neon-glow)');

        // Smart Hotspot Label Positioning with collision avoidance
        const rawName = hotspot.name.split('(')[0].trim();
        const labelW = Math.min(130, Math.max(65, rawName.length * 5.5 + 14));
        const labelH = 16;

        // Test candidate offsets
        const candidateOffsets = [
          { ox: 0, oy: -15 }, // Top
          { ox: 0, oy: 15 },  // Bottom
          { ox: labelW / 2 + 10, oy: 0 }, // Right
          { ox: -(labelW / 2 + 10), oy: 0 }, // Left
          { ox: labelW / 2 + 8, oy: -12 }, // Top-Right
          { ox: -(labelW / 2 + 8), oy: -12 } // Top-Left
        ];

        let chosenOffset = candidateOffsets[0];
        for (const cand of candidateOffsets) {
          const testBox: BBox = {
            x: pos[0] + cand.ox - labelW / 2,
            y: pos[1] + cand.oy - labelH / 2,
            w: labelW,
            h: labelH
          };
          if (!isColliding(testBox, 4)) {
            chosenOffset = cand;
            break;
          }
        }

        const chosenBox: BBox = {
          x: pos[0] + chosenOffset.ox - labelW / 2,
          y: pos[1] + chosenOffset.oy - labelH / 2,
          w: labelW,
          h: labelH
        };
        occupiedBoxes.push(chosenBox);

        const labelG = hotspotLabelsGroup.append('g')
          .attr('transform', `translate(${pos[0] + chosenOffset.ox}, ${pos[1] + chosenOffset.oy})`)
          .attr('class', 'cursor-pointer')
          .on('click', () => setSelectedHotspot(hotspot));

        labelG.append('rect')
          .attr('x', -labelW / 2)
          .attr('y', -labelH / 2)
          .attr('width', labelW)
          .attr('height', labelH)
          .attr('rx', 4)
          .attr('fill', '#020617')
          .attr('fill-opacity', 0.92)
          .attr('stroke', '#334155')
          .attr('stroke-width', 0.8);

        labelG.append('text')
          .text(rawName)
          .attr('x', 0)
          .attr('y', 3.2)
          .attr('text-anchor', 'middle')
          .attr('font-size', '8px')
          .attr('font-weight', 'bold')
          .attr('fill', '#cbd5e1')
          .attr('pointer-events', 'none');
      }
    });

    // Inbound Attack Arcs converging directly into User's Network
    const arcGroup = g.append('g').attr('class', 'attack-arcs');
    const particleGroup = g.append('g').attr('class', 'attack-particles');
    const badgesGroup = g.append('g').attr('class', 'speed-badges-layer');

    interface ArcEntry {
      attack: GlobalThreatAttack;
      srcPos: [number, number];
      tgtPos: [number, number];
      ctrlPos: [number, number];
      pathStr: string;
      color: string;
    }

    const arcEntries: ArcEntry[] = [];

    filteredAttacks.forEach((atk, atkIdx) => {
      const srcPos = projection([atk.source.lng, atk.source.lat]);
      const tgtPos = projection([atk.target.lng, atk.target.lat]);
      if (!srcPos || !tgtPos) return;

      const dx = tgtPos[0] - srcPos[0];
      const dy = tgtPos[1] - srcPos[1];
      const dist = Math.sqrt(dx * dx + dy * dy);

      const midX = (srcPos[0] + tgtPos[0]) / 2;
      const midY = (srcPos[1] + tgtPos[1]) / 2;
      const arcHeight = Math.min(110, Math.max(30, dist * 0.28));
      const ctrlPos: [number, number] = [midX, midY - arcHeight];

      const pathStr = `M ${srcPos[0]} ${srcPos[1]} Q ${ctrlPos[0]} ${ctrlPos[1]} ${tgtPos[0]} ${tgtPos[1]}`;
      const color = atk.severity === 'Critical' ? '#f43f5e' : atk.severity === 'High' ? '#fb923c' : '#38bdf8';

      arcEntries.push({ attack: atk, srcPos, tgtPos, ctrlPos, pathStr, color });

      // Arc Trajectory Line
      arcGroup.append('path')
        .attr('d', pathStr)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', atk.severity === 'Critical' ? 1.8 : 1.2)
        .attr('stroke-dasharray', atk.severity === 'Critical' ? '5 2' : 'none')
        .attr('stroke-opacity', selectedAttack?.id === atk.id ? 0.95 : 0.4)
        .attr('class', 'cursor-pointer hover:stroke-opacity-100 transition-opacity')
        .on('click', () => {
          setSelectedAttack(atk);
          if (onSelectAttack) onSelectAttack(atk);
        });

      // Mid-arc telemetry speed & packet volume pill label (when enabled)
      if (showSpeedBadges) {
        const speedText = atk.inboundMbps 
          ? `${atk.inboundMbps >= 1000 ? (atk.inboundMbps / 1000).toFixed(1) + ' Gbps' : atk.inboundMbps + ' Mbps'}`
          : `${atk.bandwidthGbps} Gbps`;

        const badgeWidth = 78;
        const badgeHeight = 16;

        // Evaluate candidate fractions t along quadratic Bezier curve
        // B(t) = (1-t)^2 * P0 + 2(1-t)t * P1 + t^2 * P2
        const candidateT = dist < 140 
          ? [0.20, 0.30, 0.15, 0.38] 
          : [0.28, 0.48, 0.68, 0.20, 0.38, 0.58, 0.78, 0.15];
        
        const candidateYOffsets = [0, -13, 13, -24, 24];

        let bestPos = { x: ctrlPos[0], y: ctrlPos[1] + 10 };
        let foundNonColliding = false;

        for (const t of candidateT) {
          const bx = Math.pow(1 - t, 2) * srcPos[0] + 2 * (1 - t) * t * ctrlPos[0] + Math.pow(t, 2) * tgtPos[0];
          const by = Math.pow(1 - t, 2) * srcPos[1] + 2 * (1 - t) * t * ctrlPos[1] + Math.pow(t, 2) * tgtPos[1];

          for (const yOff of candidateYOffsets) {
            const testBox: BBox = {
              x: bx - badgeWidth / 2,
              y: by + yOff - badgeHeight / 2,
              w: badgeWidth,
              h: badgeHeight
            };

            if (!isColliding(testBox, 4)) {
              bestPos = { x: bx, y: by + yOff };
              foundNonColliding = true;
              occupiedBoxes.push(testBox);
              break;
            }
          }
          if (foundNonColliding) break;
        }

        // If crowded, push best position with index staggering
        if (!foundNonColliding) {
          const fallbackT = 0.25 + ((atkIdx % 3) * 0.2);
          const fbx = Math.pow(1 - fallbackT, 2) * srcPos[0] + 2 * (1 - fallbackT) * fallbackT * ctrlPos[0] + Math.pow(fallbackT, 2) * tgtPos[0];
          const fby = Math.pow(1 - fallbackT, 2) * srcPos[1] + 2 * (1 - fallbackT) * fallbackT * ctrlPos[1] + Math.pow(fallbackT, 2) * tgtPos[1];
          const fYOff = ((atkIdx % 2 === 0) ? -1 : 1) * 14;
          bestPos = { x: fbx, y: fby + fYOff };
          occupiedBoxes.push({
            x: bestPos.x - badgeWidth / 2,
            y: bestPos.y - badgeHeight / 2,
            w: badgeWidth,
            h: badgeHeight
          });
        }

        const badgeG = badgesGroup.append('g')
          .attr('transform', `translate(${bestPos.x}, ${bestPos.y})`)
          .attr('class', 'cursor-pointer select-none transition-transform')
          .on('click', () => {
            setSelectedAttack(atk);
            if (onSelectAttack) onSelectAttack(atk);
          });

        badgeG.append('rect')
          .attr('x', -badgeWidth / 2)
          .attr('y', -badgeHeight / 2)
          .attr('width', badgeWidth)
          .attr('height', badgeHeight)
          .attr('rx', 8)
          .attr('fill', '#020617')
          .attr('fill-opacity', 0.94)
          .attr('stroke', selectedAttack?.id === atk.id ? '#38bdf8' : color)
          .attr('stroke-width', selectedAttack?.id === atk.id ? 1.4 : 0.8);

        badgeG.append('text')
          .text(`⚡ ${speedText}`)
          .attr('x', 0)
          .attr('y', 3.2)
          .attr('text-anchor', 'middle')
          .attr('font-size', '8px')
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .attr('fill', selectedAttack?.id === atk.id ? '#ffffff' : color);
      }
    });

    // Central Beacon Anchor: USER'S NETWORK (Top-most priority group)
    if (userPos) {
      const userAnchor = g.append('g')
        .attr('class', 'user-network-beacon cursor-pointer')
        .attr('transform', `translate(${userPos[0]}, ${userPos[1]})`);

      // Radiating ring 1
      userAnchor.append('circle')
        .attr('r', 18)
        .attr('fill', 'none')
        .attr('stroke', '#10b981')
        .attr('stroke-width', 1.5)
        .attr('stroke-dasharray', '3 3')
        .attr('opacity', 0.85);

      // Radiating ring 2
      userAnchor.append('circle')
        .attr('r', 28)
        .attr('fill', 'none')
        .attr('stroke', '#059669')
        .attr('stroke-width', 1)
        .attr('opacity', 0.5);

      // Center glowing marker
      userAnchor.append('circle')
        .attr('r', 6.5)
        .attr('fill', '#10b981')
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 2)
        .attr('filter', 'url(#neon-glow)');

      // User network badge label
      userAnchor.append('rect')
        .attr('x', -68)
        .attr('y', -30)
        .attr('width', 136)
        .attr('height', 18)
        .attr('rx', 9)
        .attr('fill', '#064e3b')
        .attr('stroke', '#10b981')
        .attr('stroke-width', 1.2);

      userAnchor.append('text')
        .text(`🎯 MẠNG CỦA BẠN`)
        .attr('x', 0)
        .attr('y', -17)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px')
        .attr('font-weight', 'bold')
        .attr('fill', '#a7f3d0')
        .attr('pointer-events', 'none');
    }

    // Particle streaming animation along Bezier arcs
    const particlesData = arcEntries.map((entry, idx) => ({
      ...entry,
      progress: (idx * 0.15) % 1.0,
      speed: 0.008 + (entry.attack.bandwidthGbps / 4000)
    }));

    const particleElements = particleGroup.selectAll('circle')
      .data(particlesData)
      .join('circle')
      .attr('r', d => d.attack.severity === 'Critical' ? 3.5 : 2.5)
      .attr('fill', d => d.color)
      .attr('filter', 'url(#neon-glow)');

    let animFrame: number;
    const tickParticles = () => {
      particlesData.forEach((p, i) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;

        const t = p.progress;
        // Bezier formula B(t)
        const bx = Math.pow(1 - t, 2) * p.srcPos[0] + 2 * (1 - t) * t * p.ctrlPos[0] + Math.pow(t, 2) * p.tgtPos[0];
        const by = Math.pow(1 - t, 2) * p.srcPos[1] + 2 * (1 - t) * t * p.ctrlPos[1] + Math.pow(t, 2) * p.tgtPos[1];

        d3.select(particleElements.nodes()[i])
          .attr('cx', bx)
          .attr('cy', by);
      });

      animFrame = requestAnimationFrame(tickParticles);
    };

    animFrame = requestAnimationFrame(tickParticles);

    return () => {
      cancelAnimationFrame(animFrame);
    };
  }, [viewMode, intelData, filteredAttacks, selectedAttack, showSpeedBadges]);

  // -------------------------------------------------------------
  // D3 Rendering: VIEW 2 - 2D SPATIAL LAN THREAT HEATMAP (Subnet Radar)
  // -------------------------------------------------------------
  useEffect(() => {
    if (viewMode !== 'lan-heat') return;
    if (!lanSvgRef.current || !intelData || !intelData.lanNodes) return;

    const svg = d3.select(lanSvgRef.current);
    svg.selectAll('*').remove();

    const width = 940;
    const height = 480;

    const defs = svg.append('defs');

    // Lan Glow Filter
    const filter = defs.append('filter')
      .attr('id', 'lan-glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    filter.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'blur');
    const merge = filter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Generate radial heat gradient for each LAN node
    intelData.lanNodes.forEach(node => {
      const isIsolated = isolatedNodeIds.includes(node.id);
      const grad = defs.append('radialGradient')
        .attr('id', `lan-heat-grad-${node.id}`)
        .attr('cx', '50%')
        .attr('cy', '50%')
        .attr('r', '50%');

      const coreColor = isIsolated ? '#64748b' : node.status === 'critical' ? '#ef4444' : node.status === 'warning' ? '#f59e0b' : '#10b981';
      const intensity = isIsolated ? 0.2 : (node.threatScore / 100);

      grad.append('stop').attr('offset', '0%').attr('stop-color', coreColor).attr('stop-opacity', intensity * 0.85);
      grad.append('stop').attr('offset', '55%').attr('stop-color', coreColor).attr('stop-opacity', intensity * 0.35);
      grad.append('stop').attr('offset', '100%').attr('stop-color', coreColor).attr('stop-opacity', 0);
    });

    const g = svg.append('g').attr('class', 'lan-root');

    // D3 Zoom & Pan Behavior for LAN Heatmap
    const lanZoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.6, 6]) // Zoom from 60% to 600%
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setLanZoomLevel(event.transform.k);
      });

    svg.call(lanZoomBehavior);
    lanZoomRef.current = lanZoomBehavior;

    // Restore active zoom transform if already applied
    const existingTransform = d3.zoomTransform(svg.node()!);
    if (existingTransform && (existingTransform.k !== 1 || existingTransform.x !== 0 || existingTransform.y !== 0)) {
      g.attr('transform', existingTransform.toString());
    }

    // 1. Sonar Radar Rings & Grid
    const centerX = width / 2;
    const centerY = height / 2;
    const sonarRadii = [80, 150, 220, 290];

    sonarRadii.forEach((r, idx) => {
      g.append('circle')
        .attr('cx', centerX)
        .attr('cy', centerY)
        .attr('r', r)
        .attr('fill', 'none')
        .attr('stroke', '#1e293b')
        .attr('stroke-width', 0.8)
        .attr('stroke-dasharray', idx % 2 === 0 ? '4 4' : 'none')
        .attr('opacity', 0.6);
    });

    // Crosshairs
    g.append('line')
      .attr('x1', centerX - 300).attr('y1', centerY)
      .attr('x2', centerX + 300).attr('y2', centerY)
      .attr('stroke', '#1e293b').attr('stroke-width', 0.8).attr('stroke-dasharray', '2 4');

    g.append('line')
      .attr('x1', centerX).attr('y1', centerY - 230)
      .attr('x2', centerX).attr('y2', centerY + 230)
      .attr('stroke', '#1e293b').attr('stroke-width', 0.8).attr('stroke-dasharray', '2 4');

    // 2. Mesh Connection Links from Gateway to Nodes
    const gatewayNode = intelData.lanNodes.find(n => n.type === 'router') || intelData.lanNodes[0];
    const gwX = (gatewayNode.x / 100) * width;
    const gwY = (gatewayNode.y / 100) * height;

    const linksGroup = g.append('g').attr('class', 'lan-links');
    intelData.lanNodes.forEach(node => {
      if (node.id === gatewayNode.id) return;
      const nX = (node.x / 100) * width;
      const nY = (node.y / 100) * height;

      const isIsolated = isolatedNodeIds.includes(node.id);

      linksGroup.append('line')
        .attr('x1', gwX)
        .attr('y1', gwY)
        .attr('x2', nX)
        .attr('y2', nY)
        .attr('stroke', isIsolated ? '#ef4444' : node.status === 'critical' ? '#f43f5e' : '#334155')
        .attr('stroke-width', node.status === 'critical' ? 1.5 : 1)
        .attr('stroke-dasharray', isIsolated ? '2 4' : node.status === 'critical' ? '4 3' : 'none')
        .attr('opacity', isIsolated ? 0.3 : 0.7);
    });

    // 3. Thermal Density Heat Blobs
    const heatGroup = g.append('g').attr('class', 'lan-heat-layer');
    intelData.lanNodes.forEach(node => {
      const nX = (node.x / 100) * width;
      const nY = (node.y / 100) * height;
      const radius = node.heatRadius * 1.6;

      heatGroup.append('circle')
        .attr('cx', nX)
        .attr('cy', nY)
        .attr('r', radius)
        .attr('fill', `url(#lan-heat-grad-${node.id})`)
        .attr('pointer-events', 'none');
    });

    // 4. Interactive Node Icons & Labels
    const nodesGroup = g.append('g').attr('class', 'lan-nodes-layer');
    intelData.lanNodes.forEach(node => {
      const nX = (node.x / 100) * width;
      const nY = (node.y / 100) * height;
      const isIsolated = isolatedNodeIds.includes(node.id);
      const isSelected = selectedLanNode?.id === node.id;

      const nodeG = nodesGroup.append('g')
        .attr('class', 'lan-node-anchor cursor-pointer')
        .attr('transform', `translate(${nX}, ${nY})`)
        .on('click', () => setSelectedLanNode(node));

      // Selection halo
      if (isSelected) {
        nodeG.append('circle')
          .attr('r', 24)
          .attr('fill', 'none')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 2)
          .attr('stroke-dasharray', '3 3');
      }

      // Base Circle
      const baseColor = isIsolated ? '#475569' : node.status === 'critical' ? '#ef4444' : node.status === 'warning' ? '#f59e0b' : '#10b981';
      nodeG.append('circle')
        .attr('r', node.type === 'router' ? 18 : 14)
        .attr('fill', '#090d16')
        .attr('stroke', baseColor)
        .attr('stroke-width', node.type === 'router' ? 2.5 : 2)
        .attr('filter', 'url(#lan-glow)');

      // Text status code or symbol
      const iconText = node.type === 'router' ? 'GW' : node.type === 'iot' ? 'CAM' : node.type === 'rogue' ? 'ROGUE' : node.type === 'workstation' ? 'HOST' : 'DEV';
      nodeG.append('text')
        .text(iconText)
        .attr('text-anchor', 'middle')
        .attr('y', 3.5)
        .attr('font-size', node.type === 'rogue' ? '7px' : '8px')
        .attr('font-weight', 'black')
        .attr('font-family', 'monospace')
        .attr('fill', baseColor);

      // Label Below
      nodeG.append('text')
        .text(node.name.split('(')[0].trim())
        .attr('text-anchor', 'middle')
        .attr('y', node.type === 'router' ? 32 : 26)
        .attr('font-size', '9.5px')
        .attr('font-weight', 'bold')
        .attr('fill', isIsolated ? '#64748b' : '#f1f5f9');

      nodeG.append('text')
        .text(`${node.ip} ${isIsolated ? '[ISOLATED]' : ''}`)
        .attr('text-anchor', 'middle')
        .attr('y', node.type === 'router' ? 44 : 37)
        .attr('font-size', '8.5px')
        .attr('font-family', 'monospace')
        .attr('fill', isIsolated ? '#ef4444' : '#94a3b8');
    });

  }, [viewMode, intelData, selectedLanNode, isolatedNodeIds]);

  return (
    <div className="bg-slate-950 rounded-2xl border border-slate-800 shadow-2xl overflow-hidden text-slate-100 flex flex-col">
      {/* 1. Header & Live Telemetry HUD Bar */}
      <div className="px-6 py-4 border-b border-slate-800/80 bg-slate-900/70 backdrop-blur-md flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-600 via-teal-600 to-cyan-600 flex items-center justify-center shadow-lg shadow-emerald-500/20">
            <Radar className="w-5 h-5 text-white animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-black tracking-tight text-white uppercase flex items-center gap-2">
                Bản Đồ Nhiệt Mối Đe Dọa Mạng Của Bạn
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping"></span>
                  YOUR NETWORK PERIMETER
                </span>
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              Giám sát thời gian thực các luồng quét cổng, botnet thăm dò dội vào IP công cộng và vùng rủi ro các thiết bị mạng LAN của bạn.
            </p>
          </div>
        </div>

        {/* User Network Identity Badge & Controls */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Traffic Volume Real-Time Pill */}
          {intelData?.userNetwork?.trafficTelemetry && (
            <div className="px-3 py-1.5 rounded-xl bg-slate-900/90 border border-cyan-500/30 flex items-center gap-2.5 text-xs">
              <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <div className="flex items-center gap-1.5 font-mono">
                <span className="text-slate-400 flex items-center gap-0.5">
                  <ArrowDownLeft className="w-3 h-3 text-cyan-400" /> Về:
                </span>
                <span className="text-cyan-300 font-bold">
                  {formatBytes(intelData.userNetwork.trafficTelemetry.inboundBytesTotal)}
                </span>
                <span className="text-slate-600">|</span>
                <span className="text-slate-400 flex items-center gap-0.5">
                  <ArrowUpRight className="w-3 h-3 text-emerald-400" /> Đi:
                </span>
                <span className="text-emerald-300 font-bold">
                  {formatBytes(intelData.userNetwork.trafficTelemetry.outboundBytesTotal)}
                </span>
              </div>
            </div>
          )}

          <div className="px-3 py-1.5 rounded-xl bg-slate-900/90 border border-emerald-500/30 flex items-center gap-2 text-xs">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
            <span className="text-slate-400">IP Của Bạn:</span>
            <span className="font-mono font-bold text-emerald-300">
              {intelData?.userNetwork?.clientIp || '113.161.42.189'}
            </span>
            <button
              onClick={() => setIsIpModalOpen(true)}
              className="text-[10px] px-1.5 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 ml-1 transition-all cursor-pointer"
              title="Đổi IP hoặc mạng kiểm tra"
            >
              Đổi IP
            </button>
          </div>

          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-2 text-xs">
            <Radio className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400">Chỉ Số Nguy Cơ:</span>
            <span className="font-mono font-bold text-amber-400">
              {intelData?.userNetwork?.threatExposureScore || 74}/100
            </span>
          </div>

          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-2 text-xs">
            <Flame className="w-3.5 h-3.5 text-rose-500" />
            <span className="text-slate-400">Tấn Công Dội Vào:</span>
            <span className="font-mono font-bold text-rose-400">
              {intelData?.userNetwork?.inboundProbesPerMin || 48} đợt/phút
            </span>
          </div>

          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className={`p-2 rounded-xl border transition-all cursor-pointer ${
              isLiveStreaming
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
            }`}
            title={isLiveStreaming ? 'Tạm dừng luồng giám sát' : 'Tiếp tục giám sát trực tiếp'}
          >
            {isLiveStreaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          </button>

          <button
            onClick={() => fetchUserThreats(customIpInput || undefined)}
            className="p-2 rounded-xl bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 hover:text-white transition-all cursor-pointer"
            title="Làm mới dữ liệu radar"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Mode Selector Bar (WAN Inbound Radar vs LAN Subnet Heatmap vs International Routes vs Hardening) */}
      <div className="px-6 py-2.5 bg-slate-900/40 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800">
          <button
            onClick={() => setViewMode('wan-radar')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-2 font-semibold transition-all cursor-pointer ${
              viewMode === 'wan-radar'
                ? 'bg-emerald-600 text-white shadow-xs font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Vành Đai WAN Toàn Cầu → IP Của Bạn</span>
          </button>

          <button
            onClick={() => setViewMode('routes')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-2 font-semibold transition-all cursor-pointer ${
              viewMode === 'routes'
                ? 'bg-emerald-600 text-white shadow-xs font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Gauge className="w-3.5 h-3.5" />
            <span>Tốc Độ Tuyến Quốc Tế & Dung Lượng Gói Tin</span>
          </button>

          <button
            onClick={() => setViewMode('lan-heat')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-2 font-semibold transition-all cursor-pointer ${
              viewMode === 'lan-heat'
                ? 'bg-emerald-600 text-white shadow-xs font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wifi className="w-3.5 h-3.5" />
            <span>Bản Đồ Nhiệt Không Gian Mạng LAN (192.168.1.0/24)</span>
          </button>

          <button
            onClick={() => setViewMode('hardening')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-2 font-semibold transition-all cursor-pointer ${
              viewMode === 'hardening'
                ? 'bg-emerald-600 text-white shadow-xs font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Gia Cố Router CEH v13</span>
          </button>
        </div>

        {/* Contextual Filters / Status */}
        {viewMode === 'wan-radar' && (
          <div className="flex items-center gap-2">
            <span className="text-slate-500">Lọc Vector:</span>
            <div className="flex items-center gap-1">
              {(['all', 'ddos', 'exploit', 'botnet'] as const).map(cat => (
                <button
                  key={cat}
                  onClick={() => setFilterCategory(cat)}
                  className={`px-2.5 py-1 rounded-md text-[11px] font-mono capitalize transition-all cursor-pointer ${
                    filterCategory === cat
                      ? 'bg-slate-800 text-emerald-400 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {cat === 'all' ? 'Tất cả' : cat.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        )}

        {viewMode === 'lan-heat' && (
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> An toàn (Host/Mobile)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Cảnh báo (Modem/TV)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span> Nguy cấp (Cam/Rogue)
            </span>
          </div>
        )}
      </div>

      {/* 3. Main Visualization Stage */}
      <div className="relative w-full bg-[#070b14] border-b border-slate-800 min-h-[480px] flex items-center justify-center overflow-hidden">
        {/* VIEW 1: WAN INBOUND RADAR */}
        {viewMode === 'wan-radar' && (
          <div ref={containerRef} className="w-full flex items-center justify-center p-2 relative">
            <svg
              ref={svgRef}
              viewBox="0 0 940 480"
              className="w-full h-auto max-h-[520px] select-none cursor-grab active:cursor-grabbing transition-all"
            />
            
            {/* Live In-Canvas Floating Telemetry Overlay (Perimeter) */}
            <div className="absolute top-4 left-4 p-3 rounded-xl bg-slate-950/80 backdrop-blur-md border border-slate-800 text-xs max-w-xs pointer-events-none z-10">
              <div className="text-[11px] uppercase tracking-wider font-bold text-emerald-400 flex items-center gap-1.5 mb-1.5">
                <Radar className="w-3.5 h-3.5" />
                Vành Đai Của Bạn (Perimeter)
              </div>
              <div className="space-y-1 text-slate-300 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-500">ISP:</span>
                  <span className="text-white font-bold">{intelData?.userNetwork?.isp || 'VNPT Fiber'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Vị Trí:</span>
                  <span className="text-slate-200">{intelData?.userNetwork?.city || 'Vietnam'}, {intelData?.userNetwork?.countryCode}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Cổng Nguy Cơ:</span>
                  <span className="text-rose-400 font-bold">{intelData?.userNetwork?.openPortRiskCount || 3} Cổng Mở</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Trạng Thái:</span>
                  <span className="text-emerald-400 font-bold">{intelData?.userNetwork?.firewallStatus || 'Defending'}</span>
                </div>
              </div>
            </div>

            {/* Live In-Canvas Floating Packet & Route Speed Telemetry */}
            {intelData?.userNetwork?.trafficTelemetry && (
              <div className="absolute top-4 right-4 p-3 rounded-xl bg-slate-950/85 backdrop-blur-md border border-cyan-500/30 text-xs max-w-xs shadow-xl pointer-events-none z-10">
                <div className="text-[11px] uppercase tracking-wider font-bold text-cyan-400 flex items-center justify-between mb-1.5">
                  <span className="flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    Lưu Lượng Gói Tin Đi/Về
                  </span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 font-mono border border-cyan-500/30">
                    LIVE STREAM
                  </span>
                </div>
                <div className="space-y-1.5 text-slate-300 font-mono text-[11px]">
                  <div className="flex justify-between items-center bg-slate-900/60 px-2 py-1 rounded">
                    <span className="text-slate-400 flex items-center gap-1">
                      <ArrowDownLeft className="w-3 h-3 text-cyan-400" /> Gói Đến (Inbound):
                    </span>
                    <span className="text-cyan-300 font-bold">
                      {formatBytes(intelData.userNetwork.trafficTelemetry.inboundBytesTotal)} ({formatPackets(intelData.userNetwork.trafficTelemetry.inboundPacketsTotal)})
                    </span>
                  </div>
                  <div className="flex justify-between items-center bg-slate-900/60 px-2 py-1 rounded">
                    <span className="text-slate-400 flex items-center gap-1">
                      <ArrowUpRight className="w-3 h-3 text-emerald-400" /> Gói Đi (Outbound):
                    </span>
                    <span className="text-emerald-300 font-bold">
                      {formatBytes(intelData.userNetwork.trafficTelemetry.outboundBytesTotal)} ({formatPackets(intelData.userNetwork.trafficTelemetry.outboundPacketsTotal)})
                    </span>
                  </div>
                  <div className="flex justify-between items-center pt-1 border-t border-slate-800/80 text-[10px]">
                    <span className="text-slate-500">Tốc độ hiện tại:</span>
                    <span className="text-white font-bold">
                      ↓ {intelData.userNetwork.trafficTelemetry.currentInboundSpeedMbps} Mbps / ↑ {intelData.userNetwork.trafficTelemetry.currentOutboundSpeedMbps} Mbps
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Interactive Zoom Controls Bar */}
            <div className="absolute bottom-4 right-4 flex items-center gap-1 p-1.5 rounded-xl bg-slate-950/90 backdrop-blur-md border border-slate-800 shadow-2xl z-20">
              <button
                type="button"
                onClick={() => setShowSpeedBadges(!showSpeedBadges)}
                className={`px-2 py-1 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 border transition-all cursor-pointer ${
                  showSpeedBadges
                    ? 'bg-cyan-950/70 border-cyan-500/50 text-cyan-300'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
                title={showSpeedBadges ? 'Đang bật nhãn tốc độ trên cung đường (Bấm để ẩn)' : 'Đang ẩn nhãn tốc độ (Bấm để hiện)'}
              >
                <Zap className={`w-3.5 h-3.5 ${showSpeedBadges ? 'text-cyan-400 fill-cyan-400' : 'text-slate-400'}`} />
                <span>{showSpeedBadges ? 'Nhãn Tốc Độ' : 'Ẩn Nhãn'}</span>
              </button>

              <div className="h-4 w-px bg-slate-800 mx-0.5" />

              <button
                type="button"
                onClick={() => {
                  if (svgRef.current && wanZoomRef.current) {
                    d3.select(svgRef.current).transition().duration(250).call(wanZoomRef.current.scaleBy, 1.4);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Phóng to (Cuộn con lăn chuột lên)"
              >
                <ZoomIn className="w-4 h-4 text-cyan-400" />
              </button>
              <button
                type="button"
                onClick={() => {
                  if (svgRef.current && wanZoomRef.current) {
                    d3.select(svgRef.current).transition().duration(250).call(wanZoomRef.current.scaleBy, 0.7);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Thu nhỏ (Cuộn con lăn chuột xuống)"
              >
                <ZoomOut className="w-4 h-4 text-cyan-400" />
              </button>
              <button
                type="button"
                onClick={() => {
                  if (svgRef.current && wanZoomRef.current) {
                    d3.select(svgRef.current).transition().duration(300).call(wanZoomRef.current.transform, d3.zoomIdentity);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Khôi phục kích thước ban đầu (100%)"
              >
                <RotateCcw className="w-4 h-4 text-slate-400" />
              </button>
              <div className="px-2 py-0.5 text-[11px] font-mono font-bold text-cyan-300 border-l border-slate-800">
                {Math.round(wanZoomLevel * 100)}%
              </div>
            </div>

            {/* Bottom-Left Gesture Hint */}
            <div className="absolute bottom-4 left-4 px-2.5 py-1 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800/90 text-[11px] text-slate-400 font-mono flex items-center gap-1.5 pointer-events-none z-10">
              <Move className="w-3.5 h-3.5 text-cyan-400" />
              <span>Lăn chuột để Phóng to / Thu nhỏ • Kéo để Di chuyển</span>
            </div>
          </div>
        )}

        {/* VIEW: INTERNATIONAL ROUTES SPEED & PACKET VOLUME ANALYSIS */}
        {viewMode === 'routes' && (
          <div className="w-full max-w-5xl p-6 my-4 space-y-6">
            {/* Top Stat Banner: Inbound/Outbound Packet & Volume Telemetry */}
            {intelData?.userNetwork?.trafficTelemetry && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1.5">
                      <ArrowDownLeft className="w-4 h-4 text-cyan-400" /> Dung Lượng Tải Về (Inbound)
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 font-mono">RX</span>
                  </div>
                  <div className="text-xl font-mono font-bold text-white">
                    {formatBytes(intelData.userNetwork.trafficTelemetry.inboundBytesTotal)}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    {formatPackets(intelData.userNetwork.trafficTelemetry.inboundPacketsTotal)} | Hiện tại: <span className="text-cyan-400 font-bold">{intelData.userNetwork.trafficTelemetry.currentInboundSpeedMbps} Mbps</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1.5">
                      <ArrowUpRight className="w-4 h-4 text-emerald-400" /> Dung Lượng Đẩy Đi (Outbound)
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 font-mono">TX</span>
                  </div>
                  <div className="text-xl font-mono font-bold text-white">
                    {formatBytes(intelData.userNetwork.trafficTelemetry.outboundBytesTotal)}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    {formatPackets(intelData.userNetwork.trafficTelemetry.outboundPacketsTotal)} | Hiện tại: <span className="text-emerald-400 font-bold">{intelData.userNetwork.trafficTelemetry.currentOutboundSpeedMbps} Mbps</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1.5">
                      <Gauge className="w-4 h-4 text-amber-400" /> Đỉnh Băng Thông Dội Vào
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 font-mono">PEAK</span>
                  </div>
                  <div className="text-xl font-mono font-bold text-amber-300">
                    {intelData.userNetwork.trafficTelemetry.peakInboundSpeedMbps} Mbps
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    Kích thước gói TB: <span className="text-slate-200">{intelData.userNetwork.trafficTelemetry.avgPacketSizeBytes} bytes</span>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-md">
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                    <span className="flex items-center gap-1.5">
                      <Network className="w-4 h-4 text-indigo-400" /> Luồng Quốc Tế Hoạt Động
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 font-mono">STREAMS</span>
                  </div>
                  <div className="text-xl font-mono font-bold text-indigo-300">
                    {intelData.userNetwork.trafficTelemetry.activeInternationalStreams} Tuyến
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Trực tiếp tới <span className="text-white font-bold">{intelData.userNetwork.isp}</span>
                  </div>
                </div>
              </div>
            )}

            {/* International Route Speeds Table & Topology to User Network */}
            <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    Bảng Đo Tốc Độ & Băng Thông Các Tuyến Quốc Tế Tới Mạng Của Bạn
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Đo lường thời gian trễ (RTT), tốc độ truyền tải thực tế, và khối lượng gói tin gửi từ các điểm trung chuyển quốc tế (Tier-1 Transit) về IP {intelData?.userNetwork?.clientIp}.
                  </p>
                </div>
                <div className="text-xs font-mono text-slate-400 hidden sm:block">
                  Cập nhật: <span className="text-emerald-400">{lastUpdated || 'Vừa xong'}</span>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px] font-mono">
                      <th className="pb-3 pl-2">Hướng Tuyến / Cụm Máy Chủ</th>
                      <th className="pb-3">Trạm Trung Chuyển (Transit)</th>
                      <th className="pb-3">Độ Trễ (Ping)</th>
                      <th className="pb-3">Tốc Độ Về Mạng Bạn</th>
                      <th className="pb-3">Gói Tin & Dung Lượng</th>
                      <th className="pb-3">Mức Độ Tắc Nghẽn</th>
                      <th className="pb-3 pr-2 text-right">Trạng Thái</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {(intelData?.internationalRoutes || []).map((route, idx) => {
                      const flag = route.originCode === 'SG' ? '🇸🇬' :
                                   route.originCode === 'HK' ? '🇭🇰' :
                                   route.originCode === 'US' ? '🇺🇸' :
                                   route.originCode === 'EU' ? '🇪🇺' :
                                   route.originCode === 'RU' ? '🇷🇺' :
                                   route.originCode === 'IN' ? '🇮🇳' :
                                   route.originCode === 'BR' ? '🇧🇷' : '🌐';
                      return (
                        <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3 pl-2">
                            <div className="flex items-center gap-2">
                              <span className="text-base">{flag}</span>
                              <div>
                                <div className="font-sans font-bold text-white flex items-center gap-1.5">
                                  {route.direction}
                                </div>
                                <div className="text-[10px] text-slate-500 font-mono">
                                  Cáp biển / Hạ tầng: {route.transitCable}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 text-slate-300">
                            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300 font-mono">
                              {route.transitCable.split('(')[0].trim()}
                            </span>
                          </td>
                          <td className="py-3">
                            <div className="flex items-center gap-1">
                              <span className={`font-bold ${route.latencyMs > 120 ? 'text-amber-400' : 'text-emerald-400'}`}>
                                {route.latencyMs} ms
                              </span>
                              <span className="text-[9px] text-slate-500">±{route.jitterMs}ms</span>
                            </div>
                          </td>
                          <td className="py-3">
                            <div>
                              <div className="text-white font-bold">
                                {route.speedMbps >= 1000 ? `${(route.speedMbps / 1000).toFixed(1)} Gbps` : `${route.speedMbps} Mbps`}
                              </div>
                              <div className="text-[10px] text-slate-500">
                                Đỉnh: {route.peakSpeedMbps} Mbps
                              </div>
                            </div>
                          </td>
                          <td className="py-3">
                            <div className="text-cyan-300 font-bold">
                              ↓ {route.inboundVolumeMB ? (route.inboundVolumeMB >= 1024 ? `${(route.inboundVolumeMB / 1024).toFixed(2)} GB` : `${route.inboundVolumeMB} MB`) : '0 MB'}
                            </div>
                            <div className="text-[10px] text-slate-400">
                              ↑ {route.outboundVolumeMB ? (route.outboundVolumeMB >= 1024 ? `${(route.outboundVolumeMB / 1024).toFixed(2)} GB` : `${route.outboundVolumeMB} MB`) : '0 MB'}
                            </div>
                            <div className="text-[9px] text-slate-500">
                              {formatPackets(route.totalPacketsIn)} gói đến
                            </div>
                          </td>
                          <td className="py-3">
                            <div className="w-24">
                              <div className="flex justify-between text-[10px] text-slate-400 mb-1">
                                <span>Mất gói: {route.packetLossPercent}%</span>
                              </div>
                              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    route.packetLossPercent > 1.5
                                      ? 'bg-rose-500'
                                      : route.packetLossPercent > 0.5
                                      ? 'bg-amber-400'
                                      : 'bg-emerald-400'
                                  }`}
                                  style={{ width: `${Math.min(Math.max(route.packetLossPercent * 25, 8), 100)}%` }}
                                ></div>
                              </div>
                            </div>
                          </td>
                          <td className="py-3 pr-2 text-right">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                              route.health === 'optimal'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : route.health === 'congested'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            }`}>
                              {route.health === 'optimal' ? 'Tối Ưu' : route.health === 'congested' ? 'Nghẽn Tuyến' : 'Đang Bị Tấn Công'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                <span>🛡️ Các tuyến quốc tế đang được tự động định tuyến qua các trạm trung chuyển CDN & ISP để giảm thiểu nghẽn cáp biển quốc tế (AAG, APG).</span>
                <span className="font-mono text-cyan-400">Mạng đích: {intelData?.userNetwork?.clientIp} ({intelData?.userNetwork?.city})</span>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: 2D SPATIAL LAN THREAT HEATMAP */}
        {viewMode === 'lan-heat' && (
          <div className="w-full flex items-center justify-center p-2 relative">
            <svg
              ref={lanSvgRef}
              viewBox="0 0 940 480"
              className="w-full h-auto max-h-[520px] select-none cursor-grab active:cursor-grabbing transition-all"
            />

            <div className="absolute top-4 left-4 p-3 rounded-xl bg-slate-950/85 backdrop-blur-md border border-slate-800 text-xs max-w-sm pointer-events-none z-10">
              <div className="text-[11px] uppercase tracking-wider font-bold text-emerald-400 flex items-center gap-1.5 mb-1">
                <Wifi className="w-3.5 h-3.5" />
                Bản Đồ Phân Phối Nhiệt Rủi Ro Subnet
              </div>
              <p className="text-[11px] text-slate-400">
                Màu sắc và bán kính nhiệt tỏa ra thể hiện mức độ nguy cơ phơi nhiễm của thiết bị trong mạng LAN đối với botnet bên ngoài.
              </p>
            </div>

            {/* Interactive Zoom Controls Bar for LAN */}
            <div className="absolute bottom-4 right-4 flex items-center gap-1 p-1.5 rounded-xl bg-slate-950/90 backdrop-blur-md border border-slate-800 shadow-2xl z-20">
              <button
                type="button"
                onClick={() => {
                  if (lanSvgRef.current && lanZoomRef.current) {
                    d3.select(lanSvgRef.current).transition().duration(250).call(lanZoomRef.current.scaleBy, 1.4);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-emerald-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Phóng to (Cuộn con lăn chuột lên)"
              >
                <ZoomIn className="w-4 h-4 text-emerald-400" />
              </button>
              <button
                type="button"
                onClick={() => {
                  if (lanSvgRef.current && lanZoomRef.current) {
                    d3.select(lanSvgRef.current).transition().duration(250).call(lanZoomRef.current.scaleBy, 0.7);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-emerald-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Thu nhỏ (Cuộn con lăn chuột xuống)"
              >
                <ZoomOut className="w-4 h-4 text-emerald-400" />
              </button>
              <button
                type="button"
                onClick={() => {
                  if (lanSvgRef.current && lanZoomRef.current) {
                    d3.select(lanSvgRef.current).transition().duration(300).call(lanZoomRef.current.transform, d3.zoomIdentity);
                  }
                }}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-emerald-500/50 transition-all cursor-pointer flex items-center justify-center"
                title="Khôi phục kích thước ban đầu (100%)"
              >
                <RotateCcw className="w-4 h-4 text-slate-400" />
              </button>
              <div className="px-2 py-0.5 text-[11px] font-mono font-bold text-emerald-300 border-l border-slate-800">
                {Math.round(lanZoomLevel * 100)}%
              </div>
            </div>

            {/* Bottom-Left Gesture Hint */}
            <div className="absolute bottom-4 left-4 px-2.5 py-1 rounded-lg bg-slate-950/85 backdrop-blur-md border border-slate-800/90 text-[11px] text-slate-400 font-mono flex items-center gap-1.5 pointer-events-none z-10">
              <Move className="w-3.5 h-3.5 text-emerald-400" />
              <span>Lăn chuột để Phóng to / Thu nhỏ • Kéo để Di chuyển</span>
            </div>
          </div>
        )}

        {/* VIEW 3: CEH v13 ROUTER HARDENING MATRIX */}
        {viewMode === 'hardening' && (
          <div className="w-full max-w-4xl p-6 my-4">
            <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4 mb-6 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    Bộ Quy Tắc Gia Cố Router & Tường Lửa Mạng Của Bạn (CEH v13)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Áp dụng ngay các biện pháp kiểm soát này trên trang cấu hình Router của bạn để ngăn chặn 99% các luồng quét từ bên ngoài.
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400">Mức Độ Bảo Vệ:</div>
                  <div className="text-lg font-mono font-bold text-emerald-400">
                    {Math.round((hardeningRules.filter(r => r.status).length / hardeningRules.length) * 100)}%
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {hardeningRules.map(rule => (
                  <div
                    key={rule.id}
                    onClick={() => toggleHardeningRule(rule.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer flex items-start justify-between gap-3 ${
                      rule.status
                        ? 'bg-emerald-950/20 border-emerald-500/40 hover:bg-emerald-950/30'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {rule.status ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <ShieldX className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span className={`text-xs font-bold ${rule.status ? 'text-emerald-200' : 'text-slate-300'}`}>
                          {rule.label}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 pl-6 leading-relaxed">
                        {rule.desc}
                      </p>
                    </div>

                    <div className={`px-2 py-1 rounded text-[10px] font-mono font-bold uppercase ${
                      rule.status ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {rule.status ? 'Đã Bật' : 'Chưa Bật'}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between gap-4 text-xs text-slate-400">
                <span>💡 Truy cập địa chỉ gateway <strong>http://192.168.1.1</strong> trên trình duyệt của bạn để đăng nhập quản trị modem.</span>
                <button
                  onClick={handleGenerateAiBriefing}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-bold flex items-center gap-2 transition-all cursor-pointer shadow-lg shadow-emerald-600/20"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Hỏi AI Hướng Dẫn Chi Tiết Cho Router Của Bạn</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 4. Bottom Tactical Inspection Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-slate-800 bg-slate-900/50">
        {/* Column 1: Selected In-Flight Attack Details */}
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-bold text-slate-400 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-rose-500" />
              Đòn Tấn Công Đang Nhắm Vào Bạn
            </span>
            {selectedAttack && (
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                selectedAttack.severity === 'Critical'
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
              }`}>
                {selectedAttack.severity}
              </span>
            )}
          </div>

          {selectedAttack ? (
            <div className="space-y-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-xs font-bold text-white mb-1">
                  {selectedAttack.type}
                </div>
                <div className="text-[11px] text-slate-400 leading-relaxed mb-3">
                  {selectedAttack.description}
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-2 border-t border-slate-900">
                  <div>
                    <span className="text-slate-500">Nguồn Botnet:</span>
                    <div className="text-slate-200 font-bold">{selectedAttack.source.city}, {selectedAttack.source.country}</div>
                  </div>
                  <div>
                    <span className="text-slate-500">Mục Tiêu:</span>
                    <div className="text-emerald-400 font-bold">Mạng Của Bạn ({selectedAttack.target.city})</div>
                  </div>
                  <div>
                    <span className="text-slate-500">Băng Thông:</span>
                    <div className="text-rose-400 font-bold">{selectedAttack.bandwidthGbps} Gbps</div>
                  </div>
                  <div>
                    <span className="text-slate-500">Giao Thức:</span>
                    <div className="text-indigo-400 font-bold">{selectedAttack.protocol}</div>
                  </div>
                  {selectedAttack.inboundMbps && (
                    <div>
                      <span className="text-slate-500">Tốc Độ Về Mạng Bạn:</span>
                      <div className="text-amber-400 font-bold">⚡ {selectedAttack.inboundMbps >= 1000 ? `${(selectedAttack.inboundMbps / 1000).toFixed(1)} Gbps` : `${selectedAttack.inboundMbps} Mbps`}</div>
                    </div>
                  )}
                  {selectedAttack.packetsPerSecMpps && (
                    <div>
                      <span className="text-slate-500">Tốc Độ Gói Tin:</span>
                      <div className="text-cyan-400 font-bold">📦 {selectedAttack.packetsPerSecMpps} Mpps</div>
                    </div>
                  )}
                  {selectedAttack.volumeBytesIn && (
                    <div className="col-span-2 pt-1 border-t border-slate-900/80 flex justify-between">
                      <span className="text-slate-500">Dung Lượng Gói Tin Đã Nhận:</span>
                      <span className="text-emerald-300 font-bold">{formatBytes(selectedAttack.volumeBytesIn)} ({formatPackets(selectedAttack.totalPacketsReceived || 0)} gói)</span>
                    </div>
                  )}
                </div>
              </div>

              {selectedAttack.mitigation && (
                <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-[11px] space-y-1">
                  <div className="font-bold text-emerald-300 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Biện Pháp Khắc Phục Khuyến Nghị:
                  </div>
                  <p className="text-emerald-200/80 leading-relaxed">
                    {selectedAttack.mitigation}
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic py-8 text-center">
              Nhấp vào một luồng tấn công trên bản đồ để xem chi tiết kỹ thuật
            </div>
          )}
        </div>

        {/* Column 2: LAN Subnet Device Inspector */}
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-bold text-slate-400 flex items-center gap-2">
              <Laptop className="w-4 h-4 text-cyan-400" />
              Thiết Bị LAN Được Chọn
            </span>
            {selectedLanNode && (
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                selectedLanNode.status === 'critical'
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  : selectedLanNode.status === 'warning'
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
              }`}>
                {selectedLanNode.status.toUpperCase()}
              </span>
            )}
          </div>

          {selectedLanNode ? (
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold text-white">{selectedLanNode.name}</h4>
                  <p className="text-[11px] font-mono text-slate-400">{selectedLanNode.ip} ({selectedLanNode.mac})</p>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-500">Mức Rủi Ro:</span>
                  <div className={`text-sm font-mono font-bold ${
                    selectedLanNode.threatScore > 75 ? 'text-rose-400' : selectedLanNode.threatScore > 40 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {selectedLanNode.threatScore}/100
                  </div>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-900/80 text-[11px] text-slate-300 leading-relaxed">
                {selectedLanNode.riskDescription}
              </div>

              {selectedLanNode.openPorts.length > 0 && (
                <div className="text-[11px]">
                  <span className="text-slate-500">Cổng Dịch Vụ Đang Mở:</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedLanNode.openPorts.map(p => (
                      <span key={p} className="px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-mono text-[10px] border border-slate-700">
                        Port {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedLanNode.type !== 'workstation' && (
                <button
                  onClick={() => toggleIsolateNode(selectedLanNode.id)}
                  className={`w-full py-2 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition-all cursor-pointer ${
                    isolatedNodeIds.includes(selectedLanNode.id)
                      ? 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                      : 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/20'
                  }`}
                >
                  {isolatedNodeIds.includes(selectedLanNode.id) ? (
                    <>
                      <Unlock className="w-3.5 h-3.5" />
                      <span>Hủy Cô Lập Thiết Bị</span>
                    </>
                  ) : (
                    <>
                      <Lock className="w-3.5 h-3.5" />
                      <span>Cô Lập Thiết Bị Này Khỏi Subnet</span>
                    </>
                  )}
                </button>
              )}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic py-8 text-center">
              Chuyển sang tab LAN Subnet và nhấp vào thiết bị để kiểm tra
            </div>
          )}
        </div>

        {/* Column 3: AI SOC Threat Intelligence Copilot */}
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-bold text-slate-400 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400" />
              AI Threat Copilot Cho Mạng Của Bạn
            </span>
            <button
              onClick={handleGenerateAiBriefing}
              disabled={isGeneratingAi}
              className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-[11px] font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
            >
              <Sparkles className={`w-3 h-3 ${isGeneratingAi ? 'animate-spin' : ''}`} />
              <span>{isGeneratingAi ? 'Đang Phân Tích...' : 'Tư Vấn An Ninh'}</span>
            </button>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 min-h-[160px] max-h-[220px] overflow-y-auto text-xs text-slate-300 leading-relaxed font-sans">
            {aiBriefing ? (
              <div className="space-y-2 whitespace-pre-wrap">
                {aiBriefing}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-4 text-slate-500">
                <Sparkles className="w-6 h-6 text-slate-600 mb-2" />
                <p>Nhấn "Tư Vấn An Ninh" để AI tổng hợp đánh giá nguy cơ trực tiếp dội vào IP và router của bạn kèm hướng dẫn phòng thủ CEH v13.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Modal: Custom IP & Subnet Override */}
      {isIpModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 w-full max-w-md shadow-2xl text-slate-100">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Radar className="w-4 h-4 text-emerald-400" />
                Kiểm Tra Mối Đe Dọa Cho IP / Mạng Khác
              </h3>
              <button
                onClick={() => setIsIpModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleApplyCustomIp} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">
                  Nhập Địa Chỉ IP Công Cộng hoặc Dải Mạng Muốn Giám Sát:
                </label>
                <input
                  type="text"
                  value={customIpInput}
                  onChange={(e) => setCustomIpInput(e.target.value)}
                  placeholder="Ví dụ: 113.161.42.189 hoặc 14.162.18.99"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-white focus:outline-hidden focus:border-emerald-500"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Mặc định hệ thống tự động nhận diện IP thực tế bạn đang dùng để truy cập webapp này.
                </p>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsIpModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
                >
                  Hủy
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold transition-all shadow-xs"
                >
                  Cập Nhật Radar
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
