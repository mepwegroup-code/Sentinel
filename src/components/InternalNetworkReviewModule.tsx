import React, { useState, useEffect, useMemo } from 'react';
import {
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  Server,
  Laptop,
  Smartphone,
  Tv,
  Camera,
  Radio,
  Wifi,
  Search,
  RefreshCw,
  Sliders,
  Sparkles,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Eye,
  SlidersHorizontal,
  ChevronRight,
  TrendingUp,
  Download,
  Upload,
  Layers,
  Copy,
  Check,
  Power,
  Flame,
  Gauge,
  HelpCircle,
  Clock,
  ArrowRight,
  FileSpreadsheet,
  FileCode,
  HardDrive,
  Cpu,
  CornerDownRight,
  Filter,
  BarChart3,
  ListFilter
} from 'lucide-react';
import Markdown from 'react-markdown';
import {
  EndpointDevice,
  InternalNetworkReview,
  InternalNetworkScanResult,
  SuggestedNetworkPackage,
  InternalNetworkBottleneck
} from '../types';
import { ProvenanceBadge } from './ProvenanceBadge';
import { AgentInstructionBanner } from './AgentInstructionBanner';
import {
  notifyScanCompleted,
  notifyThreatDetected,
  notifySecuritySuccess,
  notifySecurityWarning
} from '../utils/securityToast';

interface InternalNetworkReviewModuleProps {
  theme?: 'light' | 'cyberpunk';
}

export const InternalNetworkReviewModule: React.FC<InternalNetworkReviewModuleProps> = ({ theme = 'light' }) => {
  // Navigation & Sub-views
  const [activeSubTab, setActiveSubTab] = useState<'overview' | 'endpoints' | 'copilot' | 'export'>('overview');

  // Network scan parameters
  const [subnetInput, setSubnetInput] = useState<string>('192.168.1.0/24');
  const [gatewayInput, setGatewayInput] = useState<string>('192.168.1.1');
  const [clientIpInput, setClientIpInput] = useState<string>('192.168.1.105');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);

  // Scan Data State
  const [scanResult, setScanResult] = useState<InternalNetworkScanResult | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointDevice | null>(null);

  // Simulator / What-If sliders
  const [extra4kStreams, setExtra4kStreams] = useState<number>(0);
  const [isLargeFileSync, setIsLargeFileSync] = useState<boolean>(false);
  const [isRecalculating, setIsRecalculating] = useState<boolean>(false);

  // Endpoint Filter & Search
  const [endpointSearch, setEndpointSearch] = useState<string>('');
  const [endpointTypeFilter, setEndpointTypeFilter] = useState<string>('all');
  const [endpointTrustFilter, setEndpointTrustFilter] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');

  // Action status notifications
  const [actionFeedback, setActionFeedback] = useState<{ id: string; message: string; type: 'success' | 'warning' } | null>(null);

  // Rename modal state
  const [renamingDevice, setRenamingDevice] = useState<EndpointDevice | null>(null);
  const [customNameInput, setCustomNameInput] = useState<string>('');
  const [notesInput, setNotesInput] = useState<string>('');

  // Rate limit modal state
  const [throttlingDevice, setThrottlingDevice] = useState<EndpointDevice | null>(null);
  const [limitSpeedInput, setLimitSpeedInput] = useState<string>('20');

  // AI Advisor State
  const [userAiGoal, setUserAiGoal] = useState<string>('Tối ưu hóa băng thông cho gia đình & trạm làm việc, loại bỏ giật lag khi chơi game / gọi video và bảo vệ thiết bị IoT an toàn');
  const [aiAdviceText, setAiAdviceText] = useState<string>('');
  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [copiedAi, setCopiedAi] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Initial Scan on Mount
  useEffect(() => {
    runSubnetScan();
  }, []);

  // WebRTC Local IP detection
  useEffect(() => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(() => {});
      pc.onicecandidate = (event) => {
        if (!event || !event.candidate) return;
        const candidateStr = event.candidate.candidate;
        const ipMatch = candidateStr.match(/\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch) {
          const detectedIp = ipMatch[1];
          setClientIpInput(detectedIp);
          const parts = detectedIp.split('.');
          setSubnetInput(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
          setGatewayInput(`${parts[0]}.${parts[1]}.${parts[2]}.1`);
          pc.close();
        }
      };
    } catch {}
  }, []);

  const runSubnetScan = async () => {
    setIsScanning(true);
    setScanProgress(10);
    
    const interval = setInterval(() => {
      setScanProgress(prev => (prev < 90 ? prev + 15 : prev));
    }, 150);

    try {
      const res = await fetch('/api/internal-network/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subnet: subnetInput,
          gateway: gatewayInput,
          clientIp: clientIpInput
        })
      });

      clearInterval(interval);
      setScanProgress(100);

      if (res.ok) {
        const data: InternalNetworkScanResult = await res.json();
        setScanResult(data);

        // Check if any rogue or suspicious devices detected
        const rogues = data.endpoints?.filter(e => e.deviceType === 'rogue' || e.trustLevel === 'blocked' || e.trustLevel === 'suspicious') || [];
        if (rogues.length > 0) {
          notifyThreatDetected({
            title: `Cảnh báo: Phát hiện ${rogues.length} thiết bị lạ / không tin cậy trong mạng LAN`,
            description: `IP: ${rogues.map(r => r.ip).join(', ')} - Vendor: ${rogues.map(r => r.vendor).join(', ')}`,
            level: 'high',
            host: subnetInput,
            actionTab: 'network-review'
          });
        }

        if (data.review) {
          notifyScanCompleted({
            module: 'INTERNAL NETWORK REVIEW',
            title: `Quét mạng nội bộ hoàn tất: ${data.endpoints?.length || 0} thiết bị trực tuyến`,
            summary: `Băng thông khuyến nghị: ${data.review.recommendedSpeedMbps} Mbps. Đã đánh giá tải mạng và ${data.review.bottlenecks?.length || 0} điểm nghẽn.`,
            target: subnetInput,
            hasThreats: rogues.length > 0,
            actionTab: 'network-review'
          });
        }
      }
    } catch (err) {
      console.error('Failed to run subnet scan:', err);
      notifySecurityWarning('Lỗi quét mạng nội bộ', 'Không thể kết nối đến gateway hoặc subnet không phản hồi.');
    } finally {
      setTimeout(() => {
        setIsScanning(false);
        setScanProgress(0);
      }, 300);
    }
  };

  const handleUploadedReport = async (reportData: any) => {
    setIsScanning(true);
    try {
      const res = await fetch('/api/lan-agent-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportData)
      });
      if (res.ok) {
        await runSubnetScan();
      }
    } catch (err) {
      console.error('Failed to post uploaded report:', err);
    } finally {
      setIsScanning(false);
    }
  };

  // Trigger recalculate when what-if sliders change
  const handleRecalculateReview = async (streams: number, isLargeSync: boolean) => {
    setIsRecalculating(true);
    try {
      const res = await fetch('/api/internal-network/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subnet: subnetInput,
          gateway: gatewayInput,
          clientIp: clientIpInput,
          additional4kStreams: streams,
          isLargeFileUploader: isLargeSync
        })
      });

      if (res.ok) {
        const updatedReview: InternalNetworkReview = await res.json();
        if (scanResult) {
          setScanResult({
            ...scanResult,
            review: updatedReview
          });
        }
      }
    } catch (err) {
      console.error('Recalculate error:', err);
    } finally {
      setIsRecalculating(false);
    }
  };

  // Endpoint Management Handlers
  const handleEndpointAction = async (endpointId: string, action: string, payload?: any) => {
    try {
      const res = await fetch('/api/internal-network/endpoint-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpointId, action, payload })
      });

      if (res.ok) {
        const data = await res.json();
        setActionFeedback({
          id: endpointId,
          message: data.message || 'Thao tác thành công',
          type: 'success'
        });

        notifySecuritySuccess(
          action === 'isolate' ? (payload?.isolate ? 'Đã Cách Ly Endpoint Khỏi Mạng!' : 'Đã Hủy Cách Ly Endpoint!') :
          action === 'throttle' ? `Đã Giới Hạn Băng Thông: ${payload?.limitMbps || 'Default'} Mbps` :
          action === 'set_trust' ? `Đã Cập Nhật Mức Độ Tin Cậy: ${payload?.trustLevel?.toUpperCase()}` :
          'Đã Cập Nhật Thông Tin Endpoint',
          data.message
        );

        // Update endpoint in local state
        if (scanResult) {
          const updatedEndpoints = scanResult.endpoints.map(ep => {
            if (ep.id === endpointId) {
              if (action === 'isolate') return { ...ep, isIsolated: Boolean(payload?.isolate) };
              if (action === 'throttle') return { ...ep, bandwidthLimitMbps: payload?.limitMbps ? Number(payload.limitMbps) : undefined };
              if (action === 'set_trust') return { ...ep, trustLevel: payload?.trustLevel };
              if (action === 'rename') return { ...ep, customName: payload?.customName, notes: payload?.notes };
            }
            return ep;
          });

          setScanResult({
            ...scanResult,
            endpoints: updatedEndpoints
          });

          // Refresh selected endpoint if opened
          if (selectedEndpoint && selectedEndpoint.id === endpointId) {
            const current = updatedEndpoints.find(e => e.id === endpointId);
            if (current) setSelectedEndpoint(current);
          }
        }

        setTimeout(() => setActionFeedback(null), 4000);
      }
    } catch (err) {
      console.error('Action failed:', err);
      setActionFeedback({
        id: endpointId,
        message: 'Lỗi thực hiện thao tác!',
        type: 'warning'
      });
      setTimeout(() => setActionFeedback(null), 4000);
    }
  };

  // AI Advisor generation
  const handleGenerateAiAdvice = async () => {
    if (!scanResult) return;
    setIsGeneratingAi(true);
    try {
      const res = await fetch('/api/internal-network/ai-advisor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanResult,
          userGoals: userAiGoal
        })
      });

      if (res.ok) {
        const data = await res.json();
        setAiAdviceText(data.advice || '');
      }
    } catch (err) {
      console.error('AI Advisor error:', err);
    } finally {
      setIsGeneratingAi(false);
    }
  };

  // Filtered Endpoints
  const filteredEndpoints = useMemo(() => {
    if (!scanResult?.endpoints) return [];
    return scanResult.endpoints.filter(ep => {
      // Search
      const searchLower = endpointSearch.toLowerCase();
      const matchSearch =
        !endpointSearch ||
        ep.ip.includes(searchLower) ||
        ep.mac.toLowerCase().includes(searchLower) ||
        ep.hostname.toLowerCase().includes(searchLower) ||
        (ep.customName && ep.customName.toLowerCase().includes(searchLower)) ||
        ep.vendor.toLowerCase().includes(searchLower);

      // Type Filter
      const matchType =
        endpointTypeFilter === 'all' ||
        (endpointTypeFilter === 'workstation' && (ep.deviceType === 'laptop' || ep.deviceType === 'workstation')) ||
        (endpointTypeFilter === 'server' && (ep.deviceType === 'nas_server' || ep.deviceType === 'router')) ||
        (endpointTypeFilter === 'media' && ep.deviceType === 'tv') ||
        (endpointTypeFilter === 'camera' && ep.deviceType === 'camera') ||
        (endpointTypeFilter === 'iot' && (ep.deviceType === 'iot' || ep.deviceType === 'printer')) ||
        (endpointTypeFilter === 'rogue' && ep.deviceType === 'rogue') ||
        (endpointTypeFilter === 'isolated' && ep.isIsolated);

      // Trust Filter
      const matchTrust = endpointTrustFilter === 'all' || ep.trustLevel === endpointTrustFilter;

      return matchSearch && matchType && matchTrust;
    });
  }, [scanResult?.endpoints, endpointSearch, endpointTypeFilter, endpointTrustFilter]);

  // Helper Device Icon
  const getDeviceIcon = (type: EndpointDevice['deviceType'], isIsolated: boolean) => {
    if (isIsolated) return <Lock className="w-5 h-5 text-red-500" />;
    switch (type) {
      case 'router': return <RouterIcon className="w-5 h-5 text-indigo-500" />;
      case 'nas_server': return <Server className="w-5 h-5 text-purple-500" />;
      case 'workstation':
      case 'laptop': return <Laptop className="w-5 h-5 text-blue-500" />;
      case 'tv': return <Tv className="w-5 h-5 text-cyan-500" />;
      case 'camera': return <Camera className="w-5 h-5 text-amber-500" />;
      case 'smartphone': return <Smartphone className="w-5 h-5 text-emerald-500" />;
      case 'iot':
      case 'printer': return <Radio className="w-5 h-5 text-pink-500" />;
      case 'rogue': return <AlertTriangle className="w-5 h-5 text-rose-500" />;
      default: return <Cpu className="w-5 h-5 text-slate-500" />;
    }
  };

  // Helper connection label
  const getConnectionBadge = (conn: EndpointDevice['connectionType']) => {
    switch (conn) {
      case 'ethernet_2.5g': return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">2.5GbE Ethernet</span>;
      case 'ethernet_1g': return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">Gigabit Ethernet</span>;
      case 'wifi_6_5g': return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Wi-Fi 6 (5GHz)</span>;
      case 'wifi_5g': return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">Wi-Fi 5 (5GHz)</span>;
      case 'wifi_2.4g': return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">Wi-Fi (2.4GHz)</span>;
    }
  };

  // Helper trust badge
  const getTrustBadge = (trust: EndpointDevice['trustLevel'], isIsolated: boolean) => {
    if (isIsolated) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/40 flex items-center gap-1">
          <Lock className="w-3 h-3" /> ĐÃ CÔ LẬP
        </span>
      );
    }
    switch (trust) {
      case 'trusted':
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" /> Đáng Tin Cậy
          </span>
        );
      case 'monitored':
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30 flex items-center gap-1">
            <Eye className="w-3 h-3" /> Cần Theo Dõi
          </span>
        );
      case 'suspicious':
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/40 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" /> Khả Nghi / Nguy Cấp
          </span>
        );
      case 'blocked':
        return (
          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-700 text-slate-300 border border-slate-600 flex items-center gap-1">
            <XCircle className="w-3 h-3" /> Đã Khóa
          </span>
        );
    }
  };

  const review = scanResult?.review;

  return (
    <div className="space-y-6">
      {/* Top Banner Header */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-500/30 shadow-xl text-white relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20" />
        
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/20 border border-indigo-400/30 text-indigo-300 text-xs font-semibold">
              <Network className="w-3.5 h-3.5 text-indigo-400" />
              <span>Sentinel OS • Internal Network Review & Endpoint Management Center</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-white flex flex-wrap items-center gap-3">
              <span>Đánh Giá Mạng Nội Bộ & Quản Lý Endpoint</span>
              <ProvenanceBadge
                type={scanResult?.reachable && scanResult.totalEndpointsFound > 0 ? 'measured' : 'unavailable'}
                label={scanResult?.reachable && scanResult.totalEndpointsFound > 0 ? 'Đo lường thật (Agent)' : 'Không khả dụng trên Cloud'}
              />
            </h2>
            <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
              Phân tích toàn diện lưu lượng mạng nội bộ, tự động tính toán nhu cầu băng thông (Mbps) theo số lượng thiết bị thực tế, đề xuất gói cước Internet tối ưu và cung cấp bảng điều khiển quản trị, cách ly và giới hạn tốc độ từng Endpoint.
            </p>
          </div>

          {/* Quick Subnet Scan Action Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 bg-slate-950/80 p-3 rounded-xl border border-slate-800 backdrop-blur-md shrink-0">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-slate-400 font-bold uppercase">Subnet:</span>
              <input
                type="text"
                value={subnetInput}
                onChange={(e) => setSubnetInput(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-cyan-300 w-32 focus:outline-none focus:border-cyan-400"
                placeholder="192.168.1.0/24"
              />
            </div>
            <button
              onClick={runSubnetScan}
              disabled={isScanning}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-bold font-mono flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30 transition-all cursor-pointer"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Đang quét... {scanProgress}%</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-white" />
                  <span>Quét Toàn Mạng</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Action Feedback Banner */}
        {actionFeedback && (
          <div className="mt-4 p-3 rounded-lg bg-emerald-950/90 border border-emerald-500/50 text-emerald-200 text-xs flex items-center gap-2 animate-fade-in">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-semibold">{actionFeedback.message}</span>
          </div>
        )}
      </div>

      {/* Agent Guidance Banner when Cloud Run cannot reach RFC1918 */}
      {(scanResult?.agentRequired || scanResult?.reachable === false || (scanResult && scanResult.totalEndpointsFound === 0)) && (
        <AgentInstructionBanner
          onRefresh={runSubnetScan}
          onUploadReport={handleUploadedReport}
          isRefreshing={isScanning}
        />
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex border-b border-slate-200 bg-white rounded-xl p-1 shadow-sm gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('overview')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
            activeSubTab === 'overview'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          <span>Băng Thông & Đề Xuất Gói Cước ({review?.recommendedSpeedMbps || 500} Mbps)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('endpoints')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
            activeSubTab === 'endpoints'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <Laptop className="w-4 h-4" />
          <span>Quản Lý Endpoint & Thiết Bị ({scanResult?.totalEndpointsFound || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('copilot')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
            activeSubTab === 'copilot'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <Sparkles className="w-4 h-4 text-amber-300" />
          <span>AI Chuyên Gia Tư Vấn Băng Thông</span>
        </button>

        <button
          onClick={() => setActiveSubTab('export')}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold transition-all cursor-pointer whitespace-nowrap ${
            activeSubTab === 'export'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <Download className="w-4 h-4" />
          <span>Xuất Danh Mục & Báo Cáo</span>
        </button>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SUB-VIEW 1: BANDWIDTH REVIEW & PACKAGE ADVISOR */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'overview' && review && (
        <div className="space-y-6">
          {/* Key Metrics Bento Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Metric 1: Health Score */}
            <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider">Điểm Sức Khỏe Mạng</span>
                <Activity className="w-4 h-4 text-emerald-500" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-slate-900 font-mono">{review.healthScore}</span>
                <span className="text-xs text-slate-400 font-bold">/ 100</span>
                <span className={`ml-auto px-2 py-0.5 rounded text-[11px] font-bold ${
                  review.healthScore >= 80 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'
                }`}>
                  {review.healthScore >= 80 ? 'TỐI ƯU' : 'CẦN NÂNG CẤP'}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                Đã kiểm tra {review.totalDevicesCount} thiết bị nội bộ và các nút thắt cổ chai.
              </p>
            </div>

            {/* Metric 2: Real-time & Peak Bandwidth */}
            <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider">Nhu Cầu Băng Thông Đỉnh</span>
                <TrendingUp className="w-4 h-4 text-blue-500" />
              </div>
              <div className="flex items-baseline gap-1.5">
                <span className="text-3xl font-extrabold text-blue-600 font-mono">{review.peakSimultaneousRxMbps}</span>
                <span className="text-xs font-bold text-slate-600">Mbps</span>
                <span className="text-xs text-slate-400 font-mono">↓ / ↑ {review.peakSimultaneousTxMbps} Mbps</span>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                Tải hiện tại: ↓ {review.totalBandwidthDemandRxMbps} Mbps (Đỉnh: +{review.headroomBufferPercent}% Headroom).
              </p>
            </div>

            {/* Metric 3: Recommended Package Speed */}
            <div className="p-5 rounded-2xl bg-gradient-to-br from-indigo-50 to-blue-50 border border-indigo-200 shadow-sm flex flex-col justify-between">
              <div className="flex items-center justify-between text-indigo-700 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider flex items-center gap-1">
                  <Zap className="w-3.5 h-3.5 text-amber-500 fill-amber-500" />
                  Gói Cước Khuyên Dùng
                </span>
                <span className="px-1.5 py-0.5 bg-indigo-600 text-white rounded text-[10px] font-bold">BEST P/P</span>
              </div>
              <div className="flex items-baseline gap-1.5">
                <span className="text-3xl font-extrabold text-indigo-950 font-mono">{review.recommendedSpeedMbps}</span>
                <span className="text-sm font-bold text-indigo-700">Mbps</span>
              </div>
              <p className="text-[11px] text-indigo-800/80 mt-2">
                Tối thiểu: {review.minimumRequiredSpeedMbps} Mbps • Ultra Pro: {review.proUltraSpeedMbps} Mbps.
              </p>
            </div>

            {/* Metric 4: Connected Devices */}
            <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col justify-between">
              <div className="flex items-center justify-between text-slate-500 mb-2">
                <span className="text-xs font-bold uppercase tracking-wider">Tổng Thiết Bị Kết Nối</span>
                <Laptop className="w-4 h-4 text-purple-500" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-extrabold text-slate-900 font-mono">{review.activeOnlineCount}</span>
                <span className="text-xs text-slate-400 font-bold">/ {review.totalDevicesCount} online</span>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                Bao gồm máy trạm, NAS, TV 4K OLED, Camera IP và IoT.
              </p>
            </div>
          </div>

          {/* Interactive What-If Simulator Bar */}
          <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-4 mb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <SlidersHorizontal className="w-4 h-4 text-indigo-600" />
                  Bộ Giả Lập Tải & Nhu Cầu Băng Thông Tương Lai (What-If Workload Simulator)
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Thay đổi các tham số tải để hệ thống tính toán lại dung lượng gói cước Mbps phù hợp trong tương lai.
                </p>
              </div>

              {isRecalculating && (
                <div className="flex items-center gap-2 text-xs font-bold text-indigo-600 font-mono">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Đang tính toán lại...</span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Slider 1: 4K Streams */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold">
                  <span className="text-slate-700 flex items-center gap-1.5">
                    <Tv className="w-4 h-4 text-cyan-600" />
                    Thêm Luồng Xem Video 4K HDR / Livestream (+28 Mbps/luồng):
                  </span>
                  <span className="text-indigo-600 font-bold font-mono bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
                    +{extra4kStreams} Luồng (+{extra4kStreams * 28} Mbps)
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="6"
                  step="1"
                  value={extra4kStreams}
                  onChange={(e) => {
                    const val = Number(e.target.value);
                    setExtra4kStreams(val);
                    handleRecalculateReview(val, isLargeFileSync);
                  }}
                  className="w-full accent-indigo-600 cursor-pointer"
                />
                <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                  <span>0 luồng</span>
                  <span>2 luồng (+56M)</span>
                  <span>4 luồng (+112M)</span>
                  <span>6 luồng (+168M)</span>
                </div>
              </div>

              {/* Slider 2: Large File / NAS Upload */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold">
                  <span className="text-slate-700 flex items-center gap-1.5">
                    <Server className="w-4 h-4 text-purple-600" />
                    Chế độ Sao lưu NAS / Tải Lên Video 4K & Render (+60 Mbps Upload):
                  </span>
                  <span className={`font-bold font-mono px-2 py-0.5 rounded border text-xs ${
                    isLargeFileSync ? 'bg-purple-100 text-purple-700 border-purple-300' : 'bg-slate-100 text-slate-600 border-slate-200'
                  }`}>
                    {isLargeFileSync ? 'ĐANG BẬT (+60 Mbps Tx)' : 'TẮT'}
                  </span>
                </div>
                <div className="flex items-center gap-3 pt-1">
                  <button
                    onClick={() => {
                      const next = !isLargeFileSync;
                      setIsLargeFileSync(next);
                      handleRecalculateReview(extra4kStreams, next);
                    }}
                    className={`px-4 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 border ${
                      isLargeFileSync
                        ? 'bg-purple-600 text-white border-purple-600 shadow-md shadow-purple-600/20'
                        : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-300'
                    }`}
                  >
                    <Upload className="w-3.5 h-3.5" />
                    <span>{isLargeFileSync ? 'Đang kích hoạt tải nặng' : 'Bật giả lập tải nặng'}</span>
                  </button>
                  <span className="text-[11px] text-slate-500">
                    Phù hợp kiểm tra tải khi backup NAS lên Cloud hoặc stream YouTube 4K.
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Device Traffic Breakdown & Distribution */}
          <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm">
            <h3 className="text-sm font-bold text-slate-900 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-600" />
              Phân Bổ Lưu Lượng Theo Danh Mục Thiết Bị Trong Mạng
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {review.deviceCategoryBreakdown.map((cat, idx) => (
                <div key={idx} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color }} />
                      {cat.category}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-white text-slate-600 border border-slate-200">
                      {cat.count} thiết bị
                    </span>
                  </div>
                  <div className="flex items-baseline justify-between text-xs">
                    <span className="text-slate-500 font-mono">Tải xuống:</span>
                    <span className="font-bold text-slate-900 font-mono">↓ {cat.rxMbps} Mbps</span>
                  </div>
                  <div className="flex items-baseline justify-between text-xs mt-1">
                    <span className="text-slate-500 font-mono">Tải lên:</span>
                    <span className="font-bold text-slate-700 font-mono">↑ {cat.txMbps} Mbps</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 3 Tailored Suggested ISP Packages */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-amber-500" />
                  Đề Xuất Gói Cước Mạng Phù Hợp Cho Mạng Của Bạn
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Được tính toán dựa trên tổng {review.totalDevicesCount} thiết bị, độ trễ và dung lượng tải đồng thời.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {review.packages.map((pkg) => (
                <div
                  key={pkg.id}
                  className={`p-6 rounded-2xl bg-white border transition-all flex flex-col justify-between relative shadow-sm hover:shadow-md ${
                    pkg.tier === 'recommended'
                      ? 'border-2 border-indigo-500 ring-4 ring-indigo-500/10'
                      : 'border-slate-200'
                  }`}
                >
                  {pkg.tier === 'recommended' && (
                    <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full bg-indigo-600 text-white text-[11px] font-bold shadow-md uppercase tracking-wider flex items-center gap-1">
                      <Sparkles className="w-3 h-3 text-amber-300" />
                      LỰA CHỌN TỐI ƯU NHẤT ⭐
                    </div>
                  )}

                  <div>
                    {/* Header */}
                    <div className="flex items-start justify-between gap-2 mb-3">
                      <div>
                        <h4 className="text-base font-bold text-slate-900">{pkg.name}</h4>
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{pkg.recommendedFor}</p>
                      </div>
                      <div className="text-right">
                        <span className="text-2xl font-black text-indigo-600 font-mono">{pkg.speedMbps}</span>
                        <span className="text-xs font-bold text-slate-500 block -mt-1">Mbps</span>
                      </div>
                    </div>

                    {/* Price & Suitability */}
                    <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 mb-4 flex items-center justify-between">
                      <div>
                        <span className="text-[10px] text-slate-400 font-bold uppercase block">Giá tham khảo</span>
                        <span className="text-xs font-bold text-slate-800">{pkg.estimatedPriceVndPerMonth}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-[10px] text-slate-400 font-bold uppercase block">Độ phù hợp</span>
                        <span className={`text-xs font-extrabold font-mono ${
                          pkg.suitabilityScore >= 90 ? 'text-emerald-600' : 'text-indigo-600'
                        }`}>
                          {pkg.suitabilityScore}% Match
                        </span>
                      </div>
                    </div>

                    {/* Performance Specs */}
                    <div className="space-y-2 mb-4 text-xs">
                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Xem video 4K HDR cùng lúc:</span>
                        <span className="font-bold text-slate-800 font-mono">Tối đa {pkg.maxConcurrent4kStreams} TV</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Tải game 50GB mất:</span>
                        <span className="font-bold text-indigo-600 font-mono">{pkg.gameDownloadTime50Gb}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Chất lượng gọi video / Họp:</span>
                        <span className="font-semibold text-slate-700">{pkg.videoCallQuality}</span>
                      </div>
                    </div>

                    {/* Pros */}
                    <div className="space-y-1.5 mb-4">
                      <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block">Ưu điểm:</span>
                      {pkg.pros.map((pro, pIdx) => (
                        <div key={pIdx} className="flex items-start gap-1.5 text-xs text-slate-600">
                          <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                          <span>{pro}</span>
                        </div>
                      ))}
                    </div>

                    {/* Real-world ISP Packages */}
                    <div className="p-3 rounded-xl bg-slate-900 text-slate-200 space-y-1.5 text-xs font-mono">
                      <span className="text-[10px] text-slate-400 font-bold uppercase block font-sans">
                        Gói cước tương đương tại Việt Nam:
                      </span>
                      {pkg.ispExamples.map((isp, iIdx) => (
                        <div key={iIdx} className="flex justify-between items-center text-[11px] text-slate-300">
                          <span className="font-bold text-cyan-400">{isp.provider} {isp.planName}</span>
                          <span className="text-slate-400">{isp.approxCost}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Bottlenecks & Hardware Upgrades Roadmap */}
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-500" />
              Cảnh Báo Nút Thắt Cổ Chai & Khuyến Nghị Nâng Cấp Hạ Tầng
            </h3>

            {review.bottlenecks.length === 0 ? (
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>Không phát hiện nút thắt cổ chai phần cứng nghiêm trọng. Hạ tầng mạng đang đáp ứng tốt!</span>
              </div>
            ) : (
              <div className="space-y-3">
                {review.bottlenecks.map((bn) => (
                  <div key={bn.id} className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-xs font-bold text-slate-900 flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          bn.severity === 'Critical' ? 'bg-red-500' : 'bg-amber-500'
                        }`} />
                        {bn.title}
                      </h4>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        bn.severity === 'Critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                      }`}>
                        {bn.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">{bn.description}</p>
                    <div className="pt-2 border-t border-slate-200/80 flex items-start gap-2 text-xs text-indigo-700 font-medium">
                      <CornerDownRight className="w-3.5 h-3.5 shrink-0 mt-0.5 text-indigo-600" />
                      <span><strong>Giải pháp:</strong> {bn.remediation}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Smart QoS Recommendations */}
            <div className="pt-4 border-t border-slate-200">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Gauge className="w-4 h-4 text-blue-600" />
                Quy Tắc Quản Trị Hàng Đợi Băng Thông (QoS & Bufferbloat Rules)
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {review.qosRecommendations.map((qos, qIdx) => (
                  <div key={qIdx} className="p-3 rounded-xl bg-blue-50/50 border border-blue-100 space-y-1">
                    <div className="flex items-center justify-between text-xs font-bold text-blue-900">
                      <span>{qos.rule}</span>
                    </div>
                    <p className="text-[11px] text-slate-600 leading-relaxed">{qos.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* SUB-VIEW 2: SUBNET SCANNER & ENDPOINT MANAGEMENT */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'endpoints' && scanResult && (
        <div className="space-y-4">
          {/* Subnet Scope & Discovered Stats Header Banner */}
          <div className="p-4 rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white shadow-md border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-indigo-600/30 border border-indigo-400/40 flex items-center justify-center text-cyan-300">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">Dải Mạng Nội Bộ (LAN Subnet):</span>
                  <span className="font-mono font-bold text-sm text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-700/50">
                    {scanResult.subnet}
                  </span>
                </div>
                <div className="text-[11px] text-slate-300 flex flex-wrap items-center gap-3 mt-1 font-mono">
                  <span>Subnet Mask: <strong className="text-white">255.255.255.0</strong></span>
                  <span>•</span>
                  <span>Gateway: <strong className="text-white">{scanResult.gateway}</strong></span>
                  <span>•</span>
                  <span>Phạm vi quét: <strong className="text-white">{scanResult.scannedRange}</strong></span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-xs text-slate-400">Tổng thiết bị phát hiện</div>
                <div className="text-lg font-black font-mono text-emerald-400">
                  {scanResult.totalEndpointsFound} <span className="text-xs font-normal text-slate-300">Node LAN</span>
                </div>
              </div>

              <button
                onClick={runSubnetScan}
                disabled={isScanning}
                className="px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-mono flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
                <span>Quét Lại Mạng</span>
              </button>
            </div>
          </div>

          {/* Controls & Filters Bar */}
          <div className="p-4 rounded-2xl bg-white border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            {/* Search Input */}
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={endpointSearch}
                onChange={(e) => setEndpointSearch(e.target.value)}
                placeholder="Tìm IP, MAC, Subnet, Tên thiết bị, Vendor (Apple, Cisco...)"
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-indigo-500 focus:bg-white transition-all font-mono"
              />
            </div>

            {/* Type & Trust Filters */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg text-xs font-semibold">
                <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5" />
                <select
                  value={endpointTypeFilter}
                  onChange={(e) => setEndpointTypeFilter(e.target.value)}
                  className="bg-transparent border-none text-xs text-slate-700 focus:outline-none cursor-pointer pr-2"
                >
                  <option value="all">Tất cả loại thiết bị ({scanResult.endpoints.length})</option>
                  <option value="workstation">Máy tính & Laptop</option>
                  <option value="server">NAS & Router</option>
                  <option value="media">Smart TV 4K</option>
                  <option value="camera">Camera IP</option>
                  <option value="iot">IoT & Smart Home</option>
                  <option value="rogue">Thiết bị lạ / Nghi vấn</option>
                  <option value="isolated">Đang bị cô lập</option>
                </select>
              </div>

              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg text-xs font-semibold">
                <select
                  value={endpointTrustFilter}
                  onChange={(e) => setEndpointTrustFilter(e.target.value)}
                  className="bg-transparent border-none text-xs text-slate-700 focus:outline-none cursor-pointer pr-2"
                >
                  <option value="all">Tất cả mức độ tin cậy</option>
                  <option value="trusted">Đáng tin cậy</option>
                  <option value="monitored">Cần theo dõi</option>
                  <option value="suspicious">Khả nghi / Nguy hiểm</option>
                  <option value="blocked">Đã chặn</option>
                </select>
              </div>

              {/* View Mode Toggle */}
              <div className="flex items-center border border-slate-200 rounded-lg p-0.5 bg-slate-50">
                <button
                  onClick={() => setViewMode('cards')}
                  className={`px-2 py-1 rounded text-xs font-semibold transition-all cursor-pointer ${
                    viewMode === 'cards' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-500'
                  }`}
                >
                  Thẻ Card
                </button>
                <button
                  onClick={() => setViewMode('table')}
                  className={`px-2 py-1 rounded text-xs font-semibold transition-all cursor-pointer ${
                    viewMode === 'table' ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-500'
                  }`}
                >
                  Bảng Danh Sách Đầy Đủ
                </button>
              </div>
            </div>
          </div>

          {/* View Mode: Cards Grid */}
          {viewMode === 'cards' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredEndpoints.map((ep) => (
                <div
                  key={ep.id}
                  className={`p-5 rounded-2xl bg-white border transition-all flex flex-col justify-between relative shadow-sm hover:shadow-md ${
                    ep.isIsolated
                      ? 'border-red-300 bg-red-50/20'
                      : ep.trustLevel === 'suspicious'
                      ? 'border-amber-300'
                      : 'border-slate-200'
                  }`}
                >
                  <div>
                    {/* Device Header */}
                    <div className="flex items-start justify-between gap-3 mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center border shadow-xs ${
                          ep.isIsolated
                            ? 'bg-red-100 border-red-200'
                            : 'bg-slate-100 border-slate-200'
                        }`}>
                          {getDeviceIcon(ep.deviceType, ep.isIsolated)}
                        </div>
                        <div>
                          <h4 className="text-xs font-bold text-slate-900 leading-tight">
                            {ep.customName || ep.hostname}
                          </h4>
                          <span className="text-[11px] text-slate-500 block truncate max-w-[180px]">
                            {ep.vendor}
                          </span>
                        </div>
                      </div>
                      <div>{getTrustBadge(ep.trustLevel, ep.isIsolated)}</div>
                    </div>

                    {/* Network Details: IP, MAC, Subnet */}
                    <div className="p-3 rounded-xl bg-slate-50 border border-slate-100 space-y-2 text-xs font-mono mb-3">
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Địa Chỉ IP:</span>
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">{ep.ip}</span>
                          <button
                            onClick={() => handleCopyText(ep.ip, `ip-${ep.id}`)}
                            className="p-1 rounded hover:bg-slate-200 text-slate-500 hover:text-slate-800 transition-colors cursor-pointer"
                            title="Sao chép IP"
                          >
                            {copiedKey === `ip-${ep.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </div>

                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Địa Chỉ MAC:</span>
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-700 bg-white px-1.5 py-0.5 rounded border border-slate-200 text-[11px]">{ep.mac}</span>
                          <button
                            onClick={() => handleCopyText(ep.mac, `mac-${ep.id}`)}
                            className="p-1 rounded hover:bg-slate-200 text-slate-500 hover:text-slate-800 transition-colors cursor-pointer"
                            title="Sao chép MAC"
                          >
                            {copiedKey === `mac-${ep.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </div>

                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Subnet LAN:</span>
                        <span className="font-bold text-slate-700 text-[11px] bg-slate-100 px-1.5 py-0.5 rounded">
                          {ep.subnet || scanResult.subnet || '192.168.1.0/24'}
                        </span>
                      </div>

                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Giao diện kết nối:</span>
                        <div>{getConnectionBadge(ep.connectionType)}</div>
                      </div>

                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Độ trễ (Ping):</span>
                        <span className="text-slate-800">{ep.latencyMs} ms {ep.rssiSignalDbm ? `(${ep.rssiSignalDbm} dBm)` : ''}</span>
                      </div>
                    </div>

                    {/* Bandwidth Usage & Speed Cap */}
                    <div className="space-y-1.5 mb-3 text-xs">
                      <div className="flex justify-between items-center">
                        <span className="text-slate-500">Lưu lượng thời gian thực:</span>
                        <span className="font-bold text-slate-900 font-mono">
                          ↓ {ep.currentRxMbps}M / ↑ {ep.currentTxMbps}M
                        </span>
                      </div>
                      {ep.bandwidthLimitMbps && (
                        <div className="flex justify-between items-center text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 text-[11px] font-semibold">
                          <span>Giới hạn tốc độ:</span>
                          <span className="font-mono font-bold">{ep.bandwidthLimitMbps} Mbps max</span>
                        </div>
                      )}
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-slate-400">Cổng mở phát hiện:</span>
                        <span className="font-mono text-slate-700">
                          {ep.openPorts.length > 0 ? `${ep.openPorts.length} cổng (${ep.openPorts.map(p => p.port).slice(0, 3).join(', ')}${ep.openPorts.length > 3 ? '...' : ''})` : 'Không mở cổng ngoài'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Actions Toolbar */}
                  <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-2">
                    <button
                      onClick={() => setSelectedEndpoint(ep)}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-all cursor-pointer flex items-center gap-1"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Chi tiết</span>
                    </button>

                    <div className="flex items-center gap-1.5">
                      {/* Rename / Tag */}
                      <button
                        onClick={() => {
                          setRenamingDevice(ep);
                          setCustomNameInput(ep.customName || ep.hostname);
                          setNotesInput(ep.notes || '');
                        }}
                        className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 transition-all cursor-pointer"
                        title="Đổi tên & Gắn thẻ"
                      >
                        <Sliders className="w-3.5 h-3.5" />
                      </button>

                      {/* Speed Throttling */}
                      <button
                        onClick={() => {
                          setThrottlingDevice(ep);
                          setLimitSpeedInput(ep.bandwidthLimitMbps ? String(ep.bandwidthLimitMbps) : '20');
                        }}
                        className={`p-1.5 rounded-lg transition-all cursor-pointer ${
                          ep.bandwidthLimitMbps
                            ? 'bg-amber-100 text-amber-700 hover:bg-amber-200'
                            : 'bg-slate-100 hover:bg-slate-200 text-slate-600'
                        }`}
                        title="Giới hạn tốc độ mạng (Rate Limit)"
                      >
                        <Gauge className="w-3.5 h-3.5" />
                      </button>

                      {/* WoL */}
                      <button
                        onClick={() => handleEndpointAction(ep.id, 'wake_on_lan')}
                        className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 transition-all cursor-pointer"
                        title="Gửi gói Magic Packet (Wake-on-LAN)"
                      >
                        <Power className="w-3.5 h-3.5 text-emerald-600" />
                      </button>

                      {/* Isolate / Quarantine Button */}
                      <button
                        onClick={() => handleEndpointAction(ep.id, 'isolate', { isolate: !ep.isIsolated })}
                        className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-1 ${
                          ep.isIsolated
                            ? 'bg-red-600 text-white hover:bg-red-700 shadow-xs'
                            : 'bg-slate-900 text-white hover:bg-red-600'
                        }`}
                        title={ep.isIsolated ? 'Dỡ bỏ cô lập thiết bị' : 'Cô lập thiết bị khỏi mạng LAN'}
                      >
                        {ep.isIsolated ? (
                          <>
                            <Unlock className="w-3.5 h-3.5" />
                            <span>Mở Khóa</span>
                          </>
                        ) : (
                          <>
                            <Lock className="w-3.5 h-3.5" />
                            <span>Cô Lập</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* View Mode: Data Table with Full Columns */
            <div className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-bold uppercase tracking-wider text-[10px]">
                      <th className="p-3 pl-4">Thiết Bị & Tên</th>
                      <th className="p-3">Địa Chỉ IP</th>
                      <th className="p-3">Địa Chỉ MAC</th>
                      <th className="p-3">Dải Mạng (Subnet / Mask)</th>
                      <th className="p-3">Giao Diện</th>
                      <th className="p-3">Lưu Lượng (Rx / Tx)</th>
                      <th className="p-3">Độ Trễ</th>
                      <th className="p-3">Mức Tin Cậy</th>
                      <th className="p-3 pr-4 text-right">Thao Tác</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {filteredEndpoints.map((ep) => (
                      <tr key={ep.id} className={`hover:bg-slate-50/80 transition-colors font-sans ${
                        ep.isIsolated ? 'bg-red-50/30' : ''
                      }`}>
                        <td className="p-3 pl-4">
                          <div className="flex items-center gap-2.5">
                            <div className="p-1.5 rounded-lg bg-slate-100 border border-slate-200 shrink-0">
                              {getDeviceIcon(ep.deviceType, ep.isIsolated)}
                            </div>
                            <div>
                              <div className="font-bold text-slate-900 leading-tight">{ep.customName || ep.hostname}</div>
                              <div className="text-[11px] text-slate-500">{ep.vendor}</div>
                            </div>
                          </div>
                        </td>
                        <td className="p-3 font-mono">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100">{ep.ip}</span>
                            <button
                              onClick={() => handleCopyText(ep.ip, `table-ip-${ep.id}`)}
                              className="p-1 rounded hover:bg-slate-200 text-slate-400 hover:text-slate-800 transition-colors cursor-pointer"
                              title="Sao chép IP"
                            >
                              {copiedKey === `table-ip-${ep.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        </td>
                        <td className="p-3 font-mono">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-700 bg-slate-100 px-2 py-0.5 rounded text-[11px]">{ep.mac}</span>
                            <button
                              onClick={() => handleCopyText(ep.mac, `table-mac-${ep.id}`)}
                              className="p-1 rounded hover:bg-slate-200 text-slate-400 hover:text-slate-800 transition-colors cursor-pointer"
                              title="Sao chép MAC"
                            >
                              {copiedKey === `table-mac-${ep.id}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        </td>
                        <td className="p-3 font-mono">
                          <div className="font-bold text-slate-800 text-[11px]">
                            {ep.subnet || scanResult.subnet || '192.168.1.0/24'}
                          </div>
                          <div className="text-[10px] text-slate-400">
                            Mask: 255.255.255.0 | GW: {ep.gateway || scanResult.gateway || '192.168.1.1'}
                          </div>
                        </td>
                        <td className="p-3 font-sans">
                          {getConnectionBadge(ep.connectionType)}
                        </td>
                        <td className="p-3 font-mono font-semibold text-slate-800">
                          ↓ {ep.currentRxMbps}M / ↑ {ep.currentTxMbps}M
                        </td>
                        <td className="p-3 font-mono text-slate-700">
                          {ep.latencyMs} ms
                        </td>
                        <td className="p-3 font-sans">
                          {getTrustBadge(ep.trustLevel, ep.isIsolated)}
                        </td>
                        <td className="p-3 pr-4 text-right font-sans">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => setSelectedEndpoint(ep)}
                              className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 cursor-pointer"
                              title="Xem chi tiết"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => handleEndpointAction(ep.id, 'isolate', { isolate: !ep.isIsolated })}
                              className={`p-1.5 rounded-lg cursor-pointer ${
                                ep.isIsolated
                                  ? 'bg-red-600 text-white hover:bg-red-700'
                                  : 'bg-slate-100 hover:bg-red-100 text-slate-700 hover:text-red-700'
                              }`}
                              title={ep.isIsolated ? 'Mở khóa' : 'Cô lập'}
                            >
                              <Lock className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* SUB-VIEW 3: AI NETWORK ADVISOR COPILOT */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'copilot' && (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-amber-500" />
                  AI Chuyên Gia Tư Vấn Nâng Cấp Băng Thông & An Toàn Mạng (Gemini Copilot)
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  AI sẽ đánh giá toàn bộ danh mục {scanResult?.totalEndpointsFound || 0} thiết bị, phân tích dung lượng NAS, Camera và tư vấn gói cước phù hợp.
                </p>
              </div>

              <button
                onClick={handleGenerateAiAdvice}
                disabled={isGeneratingAi}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white text-xs font-bold font-mono flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20 transition-all cursor-pointer"
              >
                {isGeneratingAi ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>AI Đang Phân Tích & Tính Toán...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4 text-amber-300" />
                    <span>Tạo Báo Cáo Tư Vấn Ngay</span>
                  </>
                )}
              </button>
            </div>

            {/* Custom User Goals Input */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
              <label className="text-xs font-bold text-slate-700 block">
                Mục tiêu hoặc Nhu cầu bổ sung của bạn:
              </label>
              <input
                type="text"
                value={userAiGoal}
                onChange={(e) => setUserAiGoal(e.target.value)}
                placeholder="Ví dụ: Cần livestream 4K không trễ, có 20 camera giám sát và máy chủ NAS cần backup nhanh"
                className="w-full px-3 py-2 text-xs bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-indigo-500 text-slate-800 font-sans"
              />
            </div>

            {/* Generated AI Advice Markdown Box */}
            {aiAdviceText ? (
              <div className="p-6 rounded-2xl bg-slate-900 text-slate-100 border border-slate-800 shadow-xl space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-2">
                    <Sparkles className="w-4 h-4" />
                    Báo Cáo Tư Vấn Kiến Trúc Mạng & Gói Cước Tối Ưu
                  </span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(aiAdviceText);
                      setCopiedAi(true);
                      setTimeout(() => setCopiedAi(false), 2000);
                    }}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer"
                  >
                    {copiedAi ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedAi ? 'Đã sao chép' : 'Sao chép báo cáo'}</span>
                  </button>
                </div>

                <div className="prose prose-invert prose-xs max-w-none text-slate-200 leading-relaxed font-sans">
                  <Markdown>{aiAdviceText}</Markdown>
                </div>
              </div>
            ) : (
              <div className="p-8 rounded-2xl bg-slate-50 border border-slate-200 text-center space-y-2">
                <Sparkles className="w-8 h-8 text-indigo-400 mx-auto" />
                <h4 className="text-sm font-bold text-slate-800">Chưa có bản phân tích AI</h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  Bấm nút <strong>"Tạo Báo Cáo Tư Vấn Ngay"</strong> ở trên để AI Copilot phân tích toàn diện cấu hình mạng nội bộ và đưa ra lời khuyên gói cước chính xác.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* SUB-VIEW 4: EXPORT INVENTORY & REPORT */}
      {/* ------------------------------------------------------------- */}
      {activeSubTab === 'export' && scanResult && (
        <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-6">
          <div>
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Download className="w-5 h-5 text-indigo-600" />
              Xuất Báo Cáo Kiểm Tra Mạng & Danh Mục Endpoint
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Tải xuống danh sách toàn bộ thiết bị đang kết nối mạng dưới dạng CSV hoặc cấu hình JSON.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Export CSV */}
            <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-bold text-sm text-slate-900">
                  <FileSpreadsheet className="w-4 h-4 text-emerald-600" />
                  <span>Xuất Bảng Tính CSV (Excel / Google Sheets)</span>
                </div>
                <p className="text-xs text-slate-500">
                  Bao gồm: Tên thiết bị, IP, MAC, Subnet, Subnet Mask, Gateway, Nhà sản xuất, Băng thông Rx/Tx, Độ trễ và Mức độ tin cậy.
                </p>
              </div>
              <button
                onClick={() => {
                  const headers = 'ID,Name,IP,MAC,Subnet,SubnetMask,Gateway,Vendor,Type,Connection,RxMbps,TxMbps,LatencyMs,TrustLevel,Isolated\n';
                  const rows = scanResult.endpoints.map(e => 
                    `"${e.id}","${e.customName || e.hostname}","${e.ip}","${e.mac}","${e.subnet || scanResult.subnet}","${e.subnetMask || '255.255.255.0'}","${e.gateway || scanResult.gateway}","${e.vendor}","${e.deviceType}","${e.connectionType}",${e.currentRxMbps},${e.currentTxMbps},${e.latencyMs},"${e.trustLevel}",${e.isIsolated}`
                  ).join('\n');
                  const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `lan_endpoints_inventory_${new Date().toISOString().slice(0, 10)}.csv`;
                  a.click();
                }}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold font-mono flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>Tải Bảng CSV</span>
              </button>
            </div>

            {/* Export JSON */}
            <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-bold text-sm text-slate-900">
                  <FileCode className="w-4 h-4 text-indigo-600" />
                  <span>Xuất Dữ Liệu Đầy Đủ JSON (Sentinel OS Topology)</span>
                </div>
                <p className="text-xs text-slate-500">
                  Bao gồm toàn bộ dữ liệu quét, phân tích nút thắt cổ chai, và cấu hình đề xuất gói cước.
                </p>
              </div>
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `sentinel_network_review_${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                }}
                className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold font-mono flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>Tải Tệp JSON</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* MODAL 1: ENDPOINT DEEP INSPECTOR */}
      {/* ------------------------------------------------------------- */}
      {selectedEndpoint && (
        <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-4">
            <div className="flex items-start justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-slate-100 border border-slate-200">
                  {getDeviceIcon(selectedEndpoint.deviceType, selectedEndpoint.isIsolated)}
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    {selectedEndpoint.customName || selectedEndpoint.hostname}
                  </h3>
                  <p className="text-xs text-slate-500">{selectedEndpoint.vendor}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedEndpoint(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Quick Specs Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 block text-[10px]">Địa chỉ IP:</span>
                  <button
                    onClick={() => handleCopyText(selectedEndpoint.ip, 'modal-ip')}
                    className="text-slate-400 hover:text-slate-700 cursor-pointer"
                    title="Sao chép"
                  >
                    {copiedKey === 'modal-ip' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
                <span className="font-bold text-indigo-600 text-sm">{selectedEndpoint.ip}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 block text-[10px]">Địa chỉ MAC:</span>
                  <button
                    onClick={() => handleCopyText(selectedEndpoint.mac, 'modal-mac')}
                    className="text-slate-400 hover:text-slate-700 cursor-pointer"
                    title="Sao chép"
                  >
                    {copiedKey === 'modal-mac' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
                <span className="font-bold text-slate-800 text-[11px]">{selectedEndpoint.mac}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Dải Mạng (Subnet):</span>
                <span className="font-bold text-slate-800">{selectedEndpoint.subnet || scanResult?.subnet || '192.168.1.0/24'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Subnet Mask:</span>
                <span className="font-bold text-slate-700">{selectedEndpoint.subnetMask || '255.255.255.0'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Gateway Mặc Định:</span>
                <span className="font-bold text-slate-700">{selectedEndpoint.gateway || scanResult?.gateway || '192.168.1.1'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Tốc độ liên kết:</span>
                <span className="font-bold text-emerald-600">{selectedEndpoint.linkSpeedMbps} Mbps</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Tải xuống tức thời:</span>
                <span className="font-bold text-blue-600">↓ {selectedEndpoint.currentRxMbps} Mbps</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Tải lên tức thời:</span>
                <span className="font-bold text-purple-600">↑ {selectedEndpoint.currentTxMbps} Mbps</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-slate-400 block text-[10px]">Độ trễ Ping:</span>
                <span className="font-bold text-slate-800">{selectedEndpoint.latencyMs} ms</span>
              </div>
            </div>

            {/* Open Ports & Services Audit */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                <Radio className="w-4 h-4 text-indigo-600" />
                Danh Sách Cổng Mở & Dịch Vụ Mạng ({selectedEndpoint.openPorts.length})
              </h4>
              {selectedEndpoint.openPorts.length === 0 ? (
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-100 text-xs text-slate-500">
                  Không tìm thấy cổng mở ngoài. Thiết bị ở trạng thái bảo vệ tốt.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selectedEndpoint.openPorts.map((p, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 font-bold">
                          Port {p.port}
                        </span>
                        <span className="text-slate-700 font-semibold">{p.service}</span>
                        {p.banner && <span className="text-slate-400 text-[10px]">({p.banner})</span>}
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        p.risk === 'Critical' ? 'bg-red-100 text-red-700' :
                        p.risk === 'High' ? 'bg-orange-100 text-orange-700' :
                        p.risk === 'Medium' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                      }`}>
                        {p.risk} Risk
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Action Footer in Modal */}
            <div className="pt-4 border-t border-slate-200 flex justify-between items-center">
              <button
                onClick={() => handleEndpointAction(selectedEndpoint.id, 'deep_scan')}
                className="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Quét Cổng Sâu (65.535 Ports)</span>
              </button>

              <button
                onClick={() => setSelectedEndpoint(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-900 text-white text-xs font-bold cursor-pointer"
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* MODAL 2: RENAME & CUSTOM TAG */}
      {/* ------------------------------------------------------------- */}
      {renamingDevice && (
        <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-indigo-600" />
              Đổi Tên & Gắn Nhãn Thiết Bị
            </h3>
            <p className="text-xs text-slate-500">
              Đặt tên gợi nhớ để dễ dàng theo dõi và quản lý thiết bị này ({renamingDevice.ip}).
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="font-bold text-slate-700 block mb-1">Tên Tùy Chỉnh:</label>
                <input
                  type="text"
                  value={customNameInput}
                  onChange={(e) => setCustomNameInput(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 font-sans focus:outline-none focus:border-indigo-500"
                  placeholder="Ví dụ: MacBook Làm Việc Của Nam"
                />
              </div>

              <div>
                <label className="font-bold text-slate-700 block mb-1">Ghi Chú / Phân Loại:</label>
                <input
                  type="text"
                  value={notesInput}
                  onChange={(e) => setNotesInput(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 font-sans focus:outline-none focus:border-indigo-500"
                  placeholder="Ví dụ: Phòng 302, Tầng 3"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
              <button
                onClick={() => setRenamingDevice(null)}
                className="px-3 py-1.5 rounded-lg text-slate-600 hover:bg-slate-100 text-xs font-semibold cursor-pointer"
              >
                Hủy
              </button>
              <button
                onClick={() => {
                  handleEndpointAction(renamingDevice.id, 'rename', {
                    customName: customNameInput,
                    notes: notesInput
                  });
                  setRenamingDevice(null);
                }}
                className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold cursor-pointer"
              >
                Lưu Thay Đổi
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* MODAL 3: BANDWIDTH THROTTLING / RATE LIMIT */}
      {/* ------------------------------------------------------------- */}
      {throttlingDevice && (
        <div className="fixed inset-0 bg-slate-950/70 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Gauge className="w-4 h-4 text-amber-500" />
              Giới Hạn Tốc Độ Băng Thông (Rate Limiting QoS)
            </h3>
            <p className="text-xs text-slate-500">
              Thiết lập hạn mức tốc độ tải tối đa (Mbps) cho thiết bị <strong>{throttlingDevice.customName || throttlingDevice.hostname}</strong> ({throttlingDevice.ip}).
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="font-bold text-slate-700 block mb-1">Giới Hạn Tốc Độ Tối Đa (Mbps):</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    value={limitSpeedInput}
                    onChange={(e) => setLimitSpeedInput(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 font-mono font-bold text-base focus:outline-none focus:border-amber-500"
                    placeholder="20"
                  />
                  <span className="font-bold text-slate-600 font-mono">Mbps</span>
                </div>
              </div>

              <div className="flex gap-2 text-[11px] font-mono">
                <button
                  type="button"
                  onClick={() => setLimitSpeedInput('5')}
                  className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 rounded border border-slate-200 cursor-pointer"
                >
                  5 Mbps
                </button>
                <button
                  type="button"
                  onClick={() => setLimitSpeedInput('20')}
                  className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 rounded border border-slate-200 cursor-pointer"
                >
                  20 Mbps
                </button>
                <button
                  type="button"
                  onClick={() => setLimitSpeedInput('50')}
                  className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 rounded border border-slate-200 cursor-pointer"
                >
                  50 Mbps
                </button>
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-100">
              <button
                onClick={() => {
                  handleEndpointAction(throttlingDevice.id, 'throttle', { limitMbps: null });
                  setThrottlingDevice(null);
                }}
                className="text-xs text-red-600 hover:underline font-semibold cursor-pointer"
              >
                Gỡ bỏ giới hạn
              </button>
              <div className="flex gap-2">
                <button
                  onClick={() => setThrottlingDevice(null)}
                  className="px-3 py-1.5 rounded-lg text-slate-600 hover:bg-slate-100 text-xs font-semibold cursor-pointer"
                >
                  Hủy
                </button>
                <button
                  onClick={() => {
                    handleEndpointAction(throttlingDevice.id, 'throttle', { limitMbps: Number(limitSpeedInput) });
                    setThrottlingDevice(null);
                  }}
                  className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold cursor-pointer"
                >
                  Áp Dụng
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Router icon helper
function RouterIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect width="20" height="8" x="2" y="14" rx="2" />
      <path d="M6.01 18H6" />
      <path d="M10.01 18H10" />
      <path d="M15 10v4" />
      <path d="M17.84 7.17a4 4 0 0 0-5.66 0" />
      <path d="M20.66 4.34a8 8 0 0 0-11.32 0" />
    </svg>
  );
}
