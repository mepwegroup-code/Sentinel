import React, { useState } from 'react';
import { PortScanResult } from '../types';
import { 
  Terminal, Shield, Play, RefreshCw, AlertCircle, CheckCircle2, XCircle, 
  Info, Radio, ArrowRight, ArrowLeft, Globe, ExternalLink, Zap, Lock, Server 
} from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';
import { PortAccessModal } from './PortAccessModal';

interface PortScannerModuleProps {
  portData: {
    host: string;
    ip: string;
    scannedPortsCount: number;
    openPortsCount: number;
    results: PortScanResult[];
  } | null;
  isLoading: boolean;
  onScanPorts: (customPorts?: number[]) => void;
  domain: string;
}

export const PortScannerModule: React.FC<PortScannerModuleProps> = ({
  portData,
  isLoading,
  onScanPorts,
  domain
}) => {
  const [selectedScanTechnique, setSelectedScanTechnique] = useState<'syn' | 'connect' | 'xmas' | 'ack' | 'idle'>('syn');
  const [simulatedStep, setSimulatedStep] = useState(1);
  const [selectedAccessPort, setSelectedAccessPort] = useState<PortScanResult | null>(null);
  const [portPreset, setPortPreset] = useState<'all' | 'web' | 'remote' | 'db'>('all');

  const presetPortMap: Record<'all' | 'web' | 'remote' | 'db', number[] | undefined> = {
    all: undefined,
    web: [80, 443, 8080, 8443, 8888],
    remote: [21, 22, 23, 3389],
    db: [1433, 3306, 5432]
  };

  const handleScanWithPreset = (presetKey: 'all' | 'web' | 'remote' | 'db') => {
    setPortPreset(presetKey);
    onScanPorts(presetPortMap[presetKey]);
  };

  const scanTechniques = [
    {
      id: 'syn',
      name: 'Stealth SYN / Half-Open (-sS)',
      flags: 'SYN',
      description: 'Sends SYN packet; if SYN+ACK received, immediately responds with RST to avoid completing 3-way handshake and logging on victim.',
      cehReference: 'CEH v13 Module 03 (Page 47-48)',
      steps: [
        { from: 'Attacker', to: 'Target', packet: 'TCP SYN (Port 80)', desc: 'Client initiates connection' },
        { from: 'Target', to: 'Attacker', packet: 'TCP SYN + ACK', desc: 'Port is OPEN & listening' },
        { from: 'Attacker', to: 'Target', packet: 'TCP RST', desc: 'Attacker abruptly resets to avoid connection log' }
      ]
    },
    {
      id: 'connect',
      name: 'TCP Connect / Full-Open (-sT)',
      flags: 'SYN, ACK',
      description: 'Completes standard RFC 793 3-way handshake via OS connect() socket call. Highly reliable, does not require raw socket privileges.',
      cehReference: 'CEH v13 Module 03 (Page 45-46)',
      steps: [
        { from: 'Attacker', to: 'Target', packet: 'TCP SYN', desc: 'Client initiates handshake' },
        { from: 'Target', to: 'Attacker', packet: 'TCP SYN + ACK', desc: 'Server acknowledges and accepts' },
        { from: 'Attacker', to: 'Target', packet: 'TCP ACK', desc: 'Connection ESTABLISHED (logged by server)' },
        { from: 'Attacker', to: 'Target', packet: 'TCP RST / FIN', desc: 'Gracefully terminates connection' }
      ]
    },
    {
      id: 'xmas',
      name: 'Xmas Tree Scan (-sX)',
      flags: 'FIN, URG, PSH',
      description: 'Sets FIN, URG, and PSH flags ("lit up like a Christmas tree"). Compliant RFC 793 UNIX hosts drop packet if open, or return RST if closed.',
      cehReference: 'CEH v13 Module 03 (Page 50-51)',
      steps: [
        { from: 'Attacker', to: 'Target', packet: 'TCP [FIN, URG, PSH]', desc: 'Malformed inverted probe sent' },
        { from: 'Target', to: 'Attacker', packet: 'No Response', desc: 'If Port is OPEN (UNIX/BSD standard)' },
        { from: 'Target', to: 'Attacker', packet: 'TCP RST + ACK (if closed)', desc: 'If Port is CLOSED on target' }
      ]
    },
    {
      id: 'ack',
      name: 'ACK Flag Probe Scan (-sA)',
      flags: 'ACK',
      description: 'Sends unsolicited ACK packet to probe firewall filtering rules. Helps determine if firewall is stateful vs stateless.',
      cehReference: 'CEH v13 Module 03 (Page 53-56)',
      steps: [
        { from: 'Attacker', to: 'Target', packet: 'TCP ACK (Random SEQ)', desc: 'Unsolicited acknowledgment probe' },
        { from: 'Target', to: 'Attacker', packet: 'TCP RST (Window != 0)', desc: 'Unfiltered port (Passes firewall)' },
        { from: 'Target', to: 'Attacker', packet: 'ICMP Destination Unreachable / No Response', desc: 'Filtered by stateful firewall' }
      ]
    },
    {
      id: 'idle',
      name: 'IDLE / Zombie Scan (-sI)',
      flags: 'Spoofed SYN',
      description: 'True blind port scan using a silent Zombie host with predictable IP Identification (IPID) increments to hide attacker IP.',
      cehReference: 'CEH v13 Module 03 (Page 57-59)',
      steps: [
        { from: 'Attacker', to: 'Zombie Host', packet: 'SYN/ACK', desc: 'Probe Zombie current IPID (e.g. 31337)' },
        { from: 'Attacker (Spoofed as Zombie)', to: 'Target', packet: 'SYN (Port 80)', desc: 'Send spoofed packet to target' },
        { from: 'Target', to: 'Zombie', packet: 'SYN/ACK (if port open)', desc: 'Target replies to Zombie IP' },
        { from: 'Zombie', to: 'Target', packet: 'RST (IPID becomes 31338)', desc: 'Zombie increments IPID' },
        { from: 'Attacker', to: 'Zombie', packet: 'SYN/ACK', desc: 'Attacker checks IPID = 31339 (+2 = OPEN)' }
      ]
    }
  ];

  const currentTechnique = scanTechniques.find(t => t.id === selectedScanTechnique) || scanTechniques[0];

  const openPortsList = portData?.results?.filter(p => p.status === 'open') || [];

  return (
    <div className="space-y-6">
      {/* Top Header & Actions */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-blue-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              Port & Service Discovery Engine
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Target Host: <span className="font-mono font-semibold text-slate-800">{domain || 'None'}</span> ({portData?.ip || 'Resolving IP...'})
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Presets */}
          <div className="flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => handleScanWithPreset('all')}
              disabled={isLoading || !domain}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                portPreset === 'all' ? 'bg-white font-bold text-slate-800 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Tất cả (19 cổng)
            </button>
            <button
              onClick={() => handleScanWithPreset('web')}
              disabled={isLoading || !domain}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                portPreset === 'web' ? 'bg-white font-bold text-blue-600 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Web (80, 443, 8080...)
            </button>
            <button
              onClick={() => handleScanWithPreset('remote')}
              disabled={isLoading || !domain}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                portPreset === 'remote' ? 'bg-white font-bold text-indigo-600 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Quản trị (SSH, Telnet)
            </button>
            <button
              onClick={() => handleScanWithPreset('db')}
              disabled={isLoading || !domain}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                portPreset === 'db' ? 'bg-white font-bold text-amber-600 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Database (MySQL, MSSQL)
            </button>
          </div>

          <button
            id="start-port-scan-btn"
            onClick={() => handleScanWithPreset(portPreset)}
            disabled={isLoading || !domain}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Probing Services...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run TCP Port Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Accessible Open Ports Highlight Bar */}
      {openPortsList.length > 0 && (
        <div className="bg-linear-to-r from-blue-900 via-indigo-900 to-slate-900 p-4 sm:p-5 rounded-2xl text-white shadow-md border border-blue-800/40">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-400/30 flex items-center justify-center text-emerald-400">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                  Phát Hiện {openPortsList.length} Cổng Đang Mở — Có Thể Truy Cập Ngay
                </h3>
                <p className="text-[11px] text-slate-300 mt-0.5">
                  Chọn bất kỳ cổng nào bên dưới để mở giao diện kiểm tra HTTP/Web hoặc tương tác trực tiếp qua TCP Socket:
                </p>
              </div>
            </div>
            <span className="text-[10px] font-mono bg-white/10 px-2.5 py-1 rounded-full text-slate-200">
              Host: {portData?.host || domain}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
            {openPortsList.map((p) => {
              const isWeb = p.isWeb || [80, 443, 8080, 8443, 8888, 3000, 5000].includes(p.port);
              return (
                <div
                  key={p.port}
                  className="bg-white/10 hover:bg-white/15 border border-white/15 rounded-xl p-3 flex flex-col justify-between transition-all group backdrop-blur-xs"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-white text-sm">
                        {p.port}/tcp
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-400/20 text-emerald-300 font-mono font-semibold">
                        OPEN
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-300 font-mono font-medium">
                      {p.service}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 mt-1">
                    <button
                      onClick={() => setSelectedAccessPort(p)}
                      className={`flex-1 py-1.5 px-2 rounded-lg text-xs font-bold flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                        isWeb 
                          ? 'bg-blue-500 hover:bg-blue-400 text-white shadow-2xs' 
                          : 'bg-indigo-500 hover:bg-indigo-400 text-white shadow-2xs'
                      }`}
                    >
                      {isWeb ? <Globe className="w-3.5 h-3.5" /> : <Terminal className="w-3.5 h-3.5" />}
                      <span>{isWeb ? 'Truy Cập Web' : 'Kết Nối Socket'}</span>
                    </button>

                    {isWeb && p.accessUrl && (
                      <a
                        href={p.accessUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1.5 rounded-lg bg-white/20 hover:bg-white/30 text-white transition-colors cursor-pointer"
                        title="Mở trong tab trình duyệt mới"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Port Scan Results Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-600 flex items-center gap-2">
              <span>Discovered Ports & Listening Daemons</span>
              {portData && (
                <span className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded-full text-[10px] font-mono">
                  {portData.openPortsCount} Open / {portData.scannedPortsCount} Probed
                </span>
              )}
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">TCP / IP</span>
          </div>

          <div className="overflow-x-auto">
            {isLoading ? (
              <div className="py-8"><LoadingSpinner /></div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-400 uppercase text-[10px] font-semibold tracking-wider">
                    <th className="pb-2 pl-2">Port</th>
                    <th className="pb-2">Service</th>
                    <th className="pb-2">Status</th>
                    <th className="pb-2">Latency</th>
                    <th className="pb-2">Risk</th>
                    <th className="pb-2 pr-2 text-right">Truy Cập / Thao Tác</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {portData?.results && portData.results.length > 0 ? (
                    portData.results.map((p) => {
                      const isOpen = p.status === 'open';
                      const isFiltered = p.status === 'filtered';
                      const isWeb = p.isWeb || [80, 443, 8080, 8443, 8888, 3000, 5000].includes(p.port);
                      return (
                        <tr key={p.port} className={`hover:bg-slate-50 transition-colors ${isOpen ? 'bg-emerald-50/30' : ''}`}>
                          <td className="py-2.5 pl-2 font-bold text-slate-800">{p.port}/tcp</td>
                          <td className="py-2.5 text-slate-700">
                            <div className="font-semibold">{p.service}</div>
                            <div className="text-[9px] text-slate-400 font-sans">{p.description}</div>
                          </td>
                          <td className="py-2.5">
                            {isOpen ? (
                              <span className="inline-flex items-center gap-1 text-emerald-700 bg-emerald-100/80 px-2 py-0.5 rounded text-[10px] font-bold">
                                <CheckCircle2 className="w-3 h-3 text-emerald-600" /> OPEN
                              </span>
                            ) : isFiltered ? (
                              <span className="inline-flex items-center gap-1 text-amber-700 bg-amber-100/80 px-2 py-0.5 rounded text-[10px]">
                                FILTERED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-slate-400 bg-slate-100 px-2 py-0.5 rounded text-[10px]">
                                CLOSED
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 text-slate-500">{p.latencyMs ? `${p.latencyMs}ms` : '—'}</td>
                          <td className="py-2.5">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                                p.riskLevel === 'Critical'
                                  ? 'bg-red-100 text-red-800 border border-red-200'
                                  : p.riskLevel === 'High'
                                  ? 'bg-orange-100 text-orange-800'
                                  : p.riskLevel === 'Medium'
                                  ? 'bg-amber-100 text-amber-800'
                                  : 'bg-slate-100 text-slate-600'
                              }`}
                            >
                              {p.riskLevel}
                            </span>
                          </td>
                          <td className="py-2.5 pr-2 text-right">
                            {isOpen ? (
                              <div className="inline-flex items-center gap-1.5 justify-end">
                                <button
                                  onClick={() => setSelectedAccessPort(p)}
                                  className={`px-2.5 py-1 rounded-lg text-[10px] font-bold flex items-center gap-1 cursor-pointer transition-all shadow-2xs ${
                                    isWeb
                                      ? 'bg-blue-600 hover:bg-blue-700 text-white'
                                      : 'bg-slate-800 hover:bg-slate-900 text-emerald-300'
                                  }`}
                                  title="Mở giao diện truy cập và gửi request kiểm tra cổng này"
                                >
                                  {isWeb ? (
                                    <>
                                      <Globe className="w-3 h-3" />
                                      <span>Truy Cập Web</span>
                                    </>
                                  ) : (
                                    <>
                                      <Terminal className="w-3 h-3" />
                                      <span>Kết Nối Socket</span>
                                    </>
                                  )}
                                </button>
                                {isWeb && p.accessUrl && (
                                  <a
                                    href={p.accessUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-blue-600 transition-colors cursor-pointer"
                                    title="Mở URL trực tiếp trong tab mới"
                                  >
                                    <ExternalLink className="w-3 h-3" />
                                  </a>
                                )}
                              </div>
                            ) : (
                              <span className="text-slate-300 text-[10px]">—</span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                        Click "Run TCP Port Scan" to detect active services
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right Column: CEH v13 Port Scanning Interactive Lab */}
        <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-600" />
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-600">
                CEH v13 Scan Methodology Simulator
              </h3>
            </div>
            <span className="text-[10px] text-blue-600 font-bold">Module 03</span>
          </div>

          {/* Technique Selector */}
          <div className="flex flex-wrap gap-1.5 mb-4">
            {scanTechniques.map((tech) => (
              <button
                key={tech.id}
                onClick={() => {
                  setSelectedScanTechnique(tech.id as any);
                  setSimulatedStep(1);
                }}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all cursor-pointer ${
                  selectedScanTechnique === tech.id
                    ? 'bg-blue-600 text-white font-semibold shadow-2xs'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {tech.name.split(' ')[0]}
              </button>
            ))}
          </div>

          {/* Technique Details Box */}
          <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200 text-xs mb-4">
            <div className="flex justify-between items-center mb-1">
              <span className="font-bold text-slate-800">{currentTechnique.name}</span>
              <span className="font-mono text-[10px] text-blue-700 bg-blue-100 px-1.5 py-0.5 rounded">
                Flags: {currentTechnique.flags}
              </span>
            </div>
            <p className="text-slate-600 text-[11px] leading-relaxed mb-2">{currentTechnique.description}</p>
            <div className="text-[10px] text-slate-400 font-mono">{currentTechnique.cehReference}</div>
          </div>

          {/* Packet Flow Animation & Step Visualizer */}
          <div className="bg-slate-900 text-slate-200 p-4 rounded-xl font-mono text-xs flex-1 flex flex-col justify-between">
            <div className="flex justify-between items-center text-slate-400 text-[10px] border-b border-slate-800 pb-2 mb-3">
              <span>PACKET FLOW SEQUENCE</span>
              <span className="text-emerald-400">RFC 793 TCP Transmission</span>
            </div>

            <div className="space-y-2.5 my-2">
              {currentTechnique.steps.map((st, idx) => {
                const isAttackerToTarget = st.from === 'Attacker' || st.from.includes('Attacker');
                return (
                  <div
                    key={idx}
                    className="p-2 rounded bg-slate-800/80 border border-slate-700/60 text-[11px] flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 text-[10px]">#{idx + 1}</span>
                      <span className={isAttackerToTarget ? 'text-blue-400' : 'text-emerald-400'}>
                        {st.from} → {st.to}
                      </span>
                    </div>
                    <div className="text-right">
                      <span className="text-yellow-300 font-bold px-1.5 py-0.5 bg-slate-900 rounded text-[10px]">
                        {st.packet}
                      </span>
                      <div className="text-[9px] text-slate-400 mt-0.5">{st.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Passive OS TTL Inference Table from CEH */}
            <div className="mt-3 pt-3 border-t border-slate-800 text-[10px]">
              <span className="text-slate-400 block mb-1 font-sans font-bold">OS Fingerprinting via TTL (CEH Table 3.2):</span>
              <div className="grid grid-cols-3 gap-1 text-center font-mono">
                <div className="bg-slate-800 p-1 rounded">Linux: TTL 64</div>
                <div className="bg-slate-800 p-1 rounded">Windows: TTL 128</div>
                <div className="bg-slate-800 p-1 rounded">Cisco/Solaris: 255</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Port Access Modal for Web Inspector & Socket Console */}
      {selectedAccessPort && (
        <PortAccessModal
          port={selectedAccessPort}
          host={portData?.host || domain}
          onClose={() => setSelectedAccessPort(null)}
        />
      )}
    </div>
  );
};
