import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Wifi, 
  Laptop, 
  Smartphone, 
  Tv, 
  Server, 
  AlertTriangle, 
  Terminal, 
  RefreshCw, 
  Sparkles, 
  Search, 
  Lock, 
  Radio, 
  Eye, 
  XOctagon, 
  CheckCircle, 
  Network, 
  Flame, 
  Copy, 
  Check,
  ChevronRight,
  Info
} from 'lucide-react';
import Markdown from 'react-markdown';
import { LanDevice, NetworkVulnerability, ClientLanAuditResult } from '../types';
import { ProvenanceBadge } from './ProvenanceBadge';
import { AgentInstructionBanner } from './AgentInstructionBanner';

interface LanIntruderModuleProps {
  theme?: 'light' | 'cyberpunk';
}

export const LanIntruderModule: React.FC<LanIntruderModuleProps> = ({ theme = 'light' }) => {
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [clientLocalIp, setClientLocalIp] = useState<string>('192.168.1.105');
  const [clientSubnet, setClientSubnet] = useState<string>('192.168.1.0/24');
  const [clientPublicIp, setClientPublicIp] = useState<string>('113.161.72.10');
  const [filterType, setFilterType] = useState<'all' | 'rogue' | 'safe'>('all');
  
  const [auditData, setAuditData] = useState<ClientLanAuditResult | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<LanDevice | null>(null);
  
  // AI Intrusion Report State
  const [aiReport, setAiReport] = useState<string>('');
  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [showAiModal, setShowAiModal] = useState<boolean>(false);
  const [copiedAi, setCopiedAi] = useState<boolean>(false);

  // Auto-detect client local IP using WebRTC ICE candidate discovery
  useEffect(() => {
    detectLocalNetworkParams();
    runLanAudit();
  }, []);

  const detectLocalNetworkParams = () => {
    try {
      // Attempt WebRTC local IP discovery
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(() => {});
      
      pc.onicecandidate = (event) => {
        if (!event || !event.candidate) return;
        const candidateStr = event.candidate.candidate;
        // Search for IPv4 pattern like 192.168.x.x or 10.x.x.x
        const ipMatch = candidateStr.match(/\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/);
        if (ipMatch) {
          const detectedIp = ipMatch[1];
          setClientLocalIp(detectedIp);
          const parts = detectedIp.split('.');
          setClientSubnet(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
          pc.close();
        }
      };

      // Also query client network info endpoint
      fetch('/api/client-network-info')
        .then(res => res.json())
        .then(data => {
          if (data.clientIp) setClientPublicIp(data.clientIp);
        })
        .catch(() => {});
    } catch {
      // Fallback standard subnet
      setClientLocalIp('192.168.1.105');
      setClientSubnet('192.168.1.0/24');
    }
  };

  const runLanAudit = async () => {
    setIsAuditing(true);
    try {
      const res = await fetch('/api/lan-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientLocalIp,
          clientSubnet,
          clientPublicIp
        })
      });

      if (res.ok) {
        const data: ClientLanAuditResult = await res.json();
        setAuditData(data);
      }
    } catch (err) {
      console.error('LAN audit failed:', err);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleUploadedReport = async (reportData: any) => {
    setIsAuditing(true);
    try {
      const res = await fetch('/api/lan-agent-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportData)
      });
      if (res.ok) {
        await runLanAudit();
      }
    } catch (err) {
      console.error('Failed to post uploaded report:', err);
    } finally {
      setIsAuditing(false);
    }
  };

  const generateAiIntruderReport = async () => {
    if (!auditData) return;
    setIsGeneratingAi(true);
    setShowAiModal(true);
    try {
      const res = await fetch('/api/lan-intruder-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lanAuditData: auditData,
          clientIp: clientLocalIp,
          gatewayIp: auditData.gatewayIp
        })
      });

      if (res.ok) {
        const data = await res.json();
        setAiReport(data.report || 'Không nhận được dữ liệu phản hồi từ AI.');
      }
    } catch (err: any) {
      setAiReport('Đã xảy ra lỗi khi gọi AI phân tích kẻ xâm nhập: ' + (err.message || err));
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const copyAiReport = () => {
    navigator.clipboard.writeText(aiReport);
    setCopiedAi(true);
    setTimeout(() => setCopiedAi(false), 2000);
  };

  const getDeviceIcon = (type: string, isRogue: boolean) => {
    if (isRogue) return <Flame className="w-5 h-5 text-rose-600 animate-pulse" />;
    switch (type) {
      case 'Router/Gateway':
        return <Server className="w-5 h-5 text-indigo-600" />;
      case 'Workstation':
        return <Laptop className="w-5 h-5 text-blue-600" />;
      case 'Mobile Phone':
        return <Smartphone className="w-5 h-5 text-emerald-600" />;
      case 'IoT / Smart Device':
        return <Tv className="w-5 h-5 text-amber-500" />;
      default:
        return <Radio className="w-5 h-5 text-slate-500" />;
    }
  };

  const filteredDevices = auditData?.devices.filter(dev => {
    if (filterType === 'rogue') return dev.isRogue;
    if (filterType === 'safe') return !dev.isRogue;
    return true;
  }) || [];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-600 to-red-700 text-white flex items-center justify-center shadow-xs">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-black text-slate-800 tracking-tight uppercase">
                Dò Tìm Lỗ Hổng & Kẻ Xâm Nhập Mạng Của Bạn (LAN Intruder Radar)
              </h2>
              <ProvenanceBadge 
                type={auditData?.reachable && auditData.totalDevicesFound > 0 ? (auditData.source || 'measured') : 'unavailable'} 
                label={auditData?.reachable && auditData.totalDevicesFound > 0 ? 'Đo lường thật (Agent)' : 'Không khả dụng trên Cloud'}
              />
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200 uppercase">
                Client Network Defense
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Kiểm tra trực tiếp mạng LAN/Wi-Fi mà máy bạn đang sử dụng: phát hiện thiết bị lạ lén kết nối, cổng độc hại (4444/31337), kẻ nghe lén ARP Spoofing và lỗ hổng modem router.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={generateAiIntruderReport}
            disabled={isAuditing || !auditData || !auditData.reachable}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-bold transition-colors cursor-pointer disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-indigo-600" />
            <span>AI Báo Cáo Xâm Nhập</span>
          </button>

          <button
            onClick={runLanAudit}
            disabled={isAuditing}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold transition-colors shadow-xs cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isAuditing ? 'animate-spin' : ''}`} />
            <span>{isAuditing ? 'Đang Quét Subnet...' : 'Rà Quét Lại Mạng'}</span>
          </button>
        </div>
      </div>

      {/* Agent Guidance Banner when running in Cloud Run without local telemetry */}
      {(auditData?.agentRequired || auditData?.reachable === false || (auditData && auditData.devices.length === 0)) && (
        <AgentInstructionBanner
          onRefresh={runLanAudit}
          onUploadReport={handleUploadedReport}
          isRefreshing={isAuditing}
        />
      )}

      {/* Network Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Hygiene Score Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Điểm An Toàn Mạng Wi-Fi</span>
            <ProvenanceBadge type={auditData?.reachable && auditData.hygieneScore !== null ? 'measured' : 'unavailable'} />
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className={`text-4xl font-black font-mono ${
              !auditData?.reachable || auditData?.hygieneScore === null ? 'text-slate-400' :
              (auditData.hygieneScore || 0) >= 80 ? 'text-emerald-600' :
              (auditData.hygieneScore || 0) >= 50 ? 'text-amber-500' : 'text-rose-600'
            }`}>
              {!auditData?.reachable || auditData?.hygieneScore === null ? '--' : auditData.hygieneScore}
            </span>
            <span className="text-sm font-bold text-slate-400">/ 100</span>
          </div>
          <div className="text-[11px] font-semibold flex items-center gap-1">
            <span className={`w-2 h-2 rounded-full ${
              !auditData?.reachable || auditData?.hygieneScore === null ? 'bg-slate-400' :
              auditData?.securityStatus === 'SECURE' ? 'bg-emerald-500' :
              auditData?.securityStatus === 'WARNING' ? 'bg-amber-500' : 'bg-rose-500 animate-ping'
            }`}></span>
            <span className={
              !auditData?.reachable || auditData?.hygieneScore === null ? 'text-slate-500' :
              auditData?.securityStatus === 'SECURE' ? 'text-emerald-700' :
              auditData?.securityStatus === 'WARNING' ? 'text-amber-700' : 'text-rose-700'
            }>
              {!auditData?.reachable || auditData?.hygieneScore === null ? 'Cần chạy Sentinel Agent để đo lường' :
               auditData?.securityStatus === 'SECURE' ? 'Mạng an toàn, không có xâm nhập' :
               auditData?.securityStatus === 'WARNING' ? 'Cảnh báo: Có thiết bị bất thường' : 'NGUY HIỂM: Phát hiện kẻ nghe lén / xâm nhập'}
            </span>
          </div>
        </div>

        {/* Rogue / Suspicious Nodes */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Thiết Bị Khả Nghi / Lạ</span>
            <Flame className="w-4 h-4 text-rose-500" />
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-4xl font-black font-mono text-rose-600">
              {auditData?.suspiciousDevicesCount || 0}
            </span>
            <span className="text-xs font-semibold text-rose-500">Node nghi vấn</span>
          </div>
          <span className="text-[11px] text-slate-500">
            {auditData?.suspiciousDevicesCount ? 'Cần cách ly và chặn MAC ngay' : 'Không tìm thấy thiết bị xâm nhập'}
          </span>
        </div>

        {/* Subnet & Gateway */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Dải Mạng Con (Subnet)</span>
            <Network className="w-4 h-4 text-blue-500" />
          </div>
          <div className="my-2">
            <span className="text-base font-bold text-slate-800 font-mono block">
              {auditData?.subnetRange || clientSubnet}
            </span>
            <span className="text-[11px] text-slate-500">
              Gateway: <strong className="text-slate-700 font-mono">{auditData?.gatewayIp || '192.168.1.1'}</strong>
            </span>
          </div>
          <span className="text-[11px] text-blue-600 font-medium">
            IP của bạn: {clientLocalIp}
          </span>
        </div>

        {/* Identified Vulnerabilities */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold uppercase text-slate-400">Lỗ Hổng Router & Wi-Fi</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="my-3 flex items-baseline gap-2">
            <span className="text-4xl font-black font-mono text-amber-600">
              {auditData?.vulnerabilities.length || 0}
            </span>
            <span className="text-xs font-semibold text-amber-500">Lỗ hổng cấu hình</span>
          </div>
          <span className="text-[11px] text-slate-500">
            Cần tắt UPnP & đổi cổng quản trị
          </span>
        </div>
      </div>

      {/* Subnet Topology Visualizer */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
          <div>
            <h3 className="text-sm font-black text-slate-800 uppercase tracking-tight flex items-center gap-2">
              <Radio className="w-4 h-4 text-rose-600" />
              <span>Sơ Đồ Bố Trí Thiết Bị Mạng LAN (Local Subnet Topology Map)</span>
            </h3>
            <p className="text-xs text-slate-500">
              Mô hình hóa các nút thiết bị đang hoạt động trên cùng mạng Wi-Fi với bạn.
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
            <button
              onClick={() => setFilterType('all')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${filterType === 'all' ? 'bg-white text-slate-900 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'}`}
            >
              Tất cả ({auditData?.devices.length || 0})
            </button>
            <button
              onClick={() => setFilterType('rogue')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${filterType === 'rogue' ? 'bg-rose-600 text-white font-bold shadow-2xs' : 'text-slate-600 hover:text-rose-600'}`}
            >
              Kẻ xâm nhập ({auditData?.suspiciousDevicesCount || 0})
            </button>
            <button
              onClick={() => setFilterType('safe')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${filterType === 'safe' ? 'bg-white text-slate-900 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'}`}
            >
              An toàn
            </button>
          </div>
        </div>

        {/* Device Cards Grid */}
        {filteredDevices.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredDevices.map((dev) => (
              <div
                key={dev.ip}
                onClick={() => setSelectedDevice(dev)}
                className={`rounded-2xl p-4 border transition-all cursor-pointer ${
                  dev.isRogue
                    ? 'bg-rose-50/50 border-rose-200 hover:border-rose-400 hover:shadow-md'
                    : dev.deviceType === 'Router/Gateway'
                    ? 'bg-indigo-50/40 border-indigo-200 hover:border-indigo-400'
                    : 'bg-slate-50/70 border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-xl flex items-center justify-center border shadow-2xs ${
                      dev.isRogue ? 'bg-rose-100 border-rose-300' : 'bg-white border-slate-200'
                    }`}>
                      {getDeviceIcon(dev.deviceType, dev.isRogue)}
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span>{dev.hostname || dev.ip}</span>
                        {dev.ip === clientLocalIp && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-blue-100 text-blue-800">
                            Máy của bạn
                          </span>
                        )}
                      </h4>
                      <span className="text-[11px] font-mono text-slate-500 block">
                        {dev.ip}
                      </span>
                    </div>
                  </div>

                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${
                    dev.riskLevel === 'Critical' ? 'bg-red-100 text-red-800 border-red-300' :
                    dev.riskLevel === 'High' ? 'bg-rose-100 text-rose-800 border-rose-300' :
                    dev.riskLevel === 'Medium' ? 'bg-amber-100 text-amber-800 border-amber-300' :
                    'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    {dev.isRogue ? 'Kẻ Xâm Nhập' : dev.riskLevel}
                  </span>
                </div>

                <div className="mt-3 pt-3 border-t border-slate-200/60 text-[11px] text-slate-600 space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Nhà sản xuất (MAC OUI):</span>
                    <span className="font-medium text-slate-700 truncate max-w-[170px]">{dev.vendor || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Địa chỉ MAC:</span>
                    <span className="font-mono text-slate-600 font-semibold">{dev.mac || 'AA:BB:CC:DD:EE:FF'}</span>
                  </div>
                  {dev.subnet && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">Subnet:</span>
                      <span className="font-mono text-slate-700">{dev.subnet}</span>
                    </div>
                  )}
                  {dev.openPorts.length > 0 && (
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Cổng đang mở:</span>
                      <span className="font-mono font-bold text-rose-600">
                        {dev.openPorts.join(', ')}
                      </span>
                    </div>
                  )}
                </div>

                {dev.anomalyIndicators.length > 0 && (
                  <div className="mt-2.5 pt-2 border-t border-rose-100">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-rose-700 block mb-1">
                      Dấu hiệu đáng ngờ:
                    </span>
                    <ul className="text-[11px] text-rose-800 list-disc list-inside space-y-0.5 font-medium">
                      {dev.anomalyIndicators.map((ind, i) => (
                        <li key={i}>{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 text-xs text-slate-500">
            Không có thiết bị nào phù hợp với bộ lọc hiện tại hoặc chưa có dữ liệu đo lường từ Sentinel Agent.
          </div>
        )}
      </div>

      {/* Network Vulnerability Checks & Safeguards */}
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-black text-slate-800 uppercase tracking-tight flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span>Danh Sách Lỗ Hổng Bảo Mật Mạng LAN Được Phát Hiện</span>
            </h3>
            <p className="text-xs text-slate-500">
              Các lỗ hổng trên modem/router và cấu hình Wi-Fi mà kẻ tấn công có thể lợi dụng để thâm nhập.
            </p>
          </div>
        </div>

        {auditData && auditData.vulnerabilities && auditData.vulnerabilities.length > 0 ? (
          <div className="space-y-3">
            {auditData.vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col md:flex-row md:items-start justify-between gap-4"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                      vuln.severity === 'Critical' ? 'bg-red-50 text-red-700 border-red-200' :
                      vuln.severity === 'High' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                      vuln.severity === 'Medium' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-blue-50 text-blue-700 border-blue-200'
                    }`}>
                      {vuln.severity}
                    </span>
                    <span className="text-xs font-bold text-slate-500 uppercase">{vuln.category}</span>
                    <h4 className="text-xs font-bold text-slate-800">{vuln.title}</h4>
                  </div>
                  <p className="text-xs text-slate-600">{vuln.description}</p>
                  {vuln.detectedOn && (
                    <span className="text-[11px] text-slate-400 block font-mono">
                      Nút bị ảnh hưởng: {vuln.detectedOn}
                    </span>
                  )}
                </div>

                <div className="md:max-w-xs shrink-0 bg-white p-3 rounded-lg border border-slate-200 text-xs">
                  <strong className="text-[11px] text-slate-700 font-bold block mb-1">Cách khắc phục ngay:</strong>
                  <p className="text-[11px] text-slate-600">{vuln.remediation}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-6 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200 text-xs text-slate-500">
            {auditData?.reachable === false
              ? "Chưa có dữ liệu kiểm định lỗ hổng. Vui lòng kết nối Sentinel Agent trên máy cục bộ để đo lường."
              : "Chưa ghi nhận lỗ hổng nguy hiểm nào trên các thiết bị đã được rà quét thực tế."}
          </div>
        )}
      </div>

      {/* AI Intrusion Report Modal */}
      {showAiModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs transition-opacity duration-300">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-indigo-600 animate-pulse" />
                <div>
                  <h3 className="text-sm font-black text-slate-800 uppercase tracking-tight">
                    Báo Cáo Phân Tích Kẻ Xâm Nhập Bằng AI (AI Intrusion Forensics Report)
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Sentinel OS CEH v13 Forensic Engine • Hướng dẫn cô lập và trục xuất thiết bị độc hại
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setShowAiModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {isGeneratingAi ? (
                <div className="flex flex-col items-center justify-center py-16 space-y-4">
                  <div className="w-12 h-12 rounded-full border-4 border-rose-100 border-t-rose-600 animate-spin"></div>
                  <div className="text-center">
                    <p className="text-xs font-bold text-slate-800">Đang điều tra dấu vết kẻ xâm nhập...</p>
                    <p className="text-[11px] text-slate-500 mt-1 max-w-md">
                      Sentinel AI đang đối chiếu các cổng mở độc hại (4444, 31337), bảng ARP bất thường và soạn thảo hướng dẫn khóa chặn router cho bạn.
                    </p>
                  </div>
                </div>
              ) : aiReport ? (
                <div className="space-y-4">
                  <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-lg p-3 text-[11px] flex items-start gap-2">
                    <Flame className="w-4 h-4 shrink-0 mt-0.5 text-rose-600" />
                    <div>
                      <strong>Cảnh báo an ninh mạng LAN:</strong> Hãy thực hiện theo 5 bước bên dưới để đổi mật khẩu quản trị modem và kích hoạt chế độ AP Isolation để bảo vệ máy tính của bạn khỏi bị nghe lén.
                    </div>
                  </div>
                  <div className="prose prose-sm max-w-none text-slate-800 bg-slate-50 rounded-xl p-5 overflow-auto max-h-[50vh] border border-slate-200">
                    <Markdown>{aiReport}</Markdown>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-400 text-xs">
                  Không có nội dung báo cáo.
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-slate-100 flex items-center justify-between bg-slate-50">
              <div className="text-[11px] text-slate-400 hidden sm:block">
                Sử dụng các lệnh trong báo cáo trên máy tính của bạn để kiểm chứng.
              </div>
              <div className="flex items-center gap-2 ml-auto">
                <button
                  onClick={() => setShowAiModal(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer"
                >
                  Đóng
                </button>
                {aiReport && !isGeneratingAi && (
                  <button
                    onClick={copyAiReport}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-lg transition-colors flex items-center gap-1.5 text-xs cursor-pointer shadow-xs"
                  >
                    {copiedAi ? (
                      <>
                        <Check className="w-3.5 h-3.5" /> Đã Sao Chép
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" /> Sao Chép Báo Cáo
                      </>
                    )}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
