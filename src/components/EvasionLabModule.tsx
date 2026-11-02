import React, { useState } from 'react';
import { Shield, Terminal, EyeOff, Radio, Cpu, Copy, Check, Info, Layers, RefreshCw, Zap, Server, Activity } from 'lucide-react';
import { ProvenanceBadge } from './ProvenanceBadge';

interface EvasionLabProps {
  targetDomain: string;
}

export const EvasionLabModule: React.FC<EvasionLabProps> = ({ targetDomain }) => {
  const host = targetDomain || 'target.host';
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Evasion Configuration State
  const [scanType, setScanType] = useState('-sS');
  const [fragmentOption, setFragmentOption] = useState<'none' | 'fragment' | 'mtu16' | 'mtu24'>('fragment');
  const [decoyMode, setDecoyMode] = useState(true);
  const [decoyCount, setDecoyCount] = useState(4);
  const [sourcePortMode, setSourcePortMode] = useState<'none' | '53' | '88' | '20' | 'random'>('53');
  const [badChecksum, setBadChecksum] = useState(false);
  const [randomizeHosts, setRandomizeHosts] = useState(true);
  const [spoofMac, setSpoofMac] = useState<'none' | 'apple' | 'cisco' | 'dell' | 'random'>('cisco');
  const [timingTemplate, setTimingTemplate] = useState<'-T0' | '-T1' | '-T2' | '-T3' | '-T4' | '-T5'>('-T2');
  const [dataLength, setDataLength] = useState<number>(25);

  // Active Tab within Evasion Lab
  const [activeSubTab, setActiveSubTab] = useState<'generator' | 'fingerprinting' | 'hping3' | 'matrix'>('generator');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Build Generated Nmap Evasion Command
  const buildNmapCommand = () => {
    const parts = ['nmap', scanType];
    
    // Timing
    parts.push(timingTemplate);

    // Packet Fragmentation
    if (fragmentOption === 'fragment') parts.push('-f');
    if (fragmentOption === 'mtu16') parts.push('--mtu 16');
    if (fragmentOption === 'mtu24') parts.push('--mtu 24');

    // Decoys
    if (decoyMode) {
      parts.push(`-D RND:${decoyCount},ME`);
    }

    // Source Port
    if (sourcePortMode === '53') parts.push('-g 53');
    else if (sourcePortMode === '88') parts.push('-g 88');
    else if (sourcePortMode === '20') parts.push('-g 20');
    else if (sourcePortMode === 'random') parts.push('--source-port 0');

    // MAC Spoofing
    if (spoofMac !== 'none') {
      parts.push(`--spoof-mac ${spoofMac.charAt(0).toUpperCase() + spoofMac.slice(1)}`);
    }

    // Data padding
    if (dataLength > 0) {
      parts.push(`--data-length ${dataLength}`);
    }

    // Bad Checksum
    if (badChecksum) {
      parts.push('--badsum');
    }

    // Host order randomization
    if (randomizeHosts) {
      parts.push('--randomize-hosts');
    }

    parts.push(host);
    return parts.join(' ');
  };

  // Build Hping3 Evasion Command
  const buildHping3Command = () => {
    let cmd = `hping3 -S ${host} -p 80`;
    if (fragmentOption === 'fragment') cmd += ' -f';
    if (sourcePortMode === '53') cmd += ' --spoof-source-port 53';
    if (badChecksum) cmd += ' --badcksum';
    if (dataLength > 0) cmd += ` -d ${dataLength}`;
    cmd += ' --fast -c 10';
    return cmd;
  };

  const OS_FINGERPRINT_TABLE = [
    { os: 'Linux (Kernel 2.4 - 5.x)', defaultTtl: 64, windowSize: '5840 / 29200', dfBit: 'Set (1)', tos: '0x00', desc: 'Standard modern Linux stack' },
    { os: 'FreeBSD / OpenBSD', defaultTtl: 64, windowSize: '65535 / 16384', dfBit: 'Set (1)', tos: '0x00', desc: 'BSD Network Stack with large initial window' },
    { os: 'Microsoft Windows (10/11/Server 2016-2022)', defaultTtl: 128, windowSize: '8192 - 65535', dfBit: 'Set (1)', tos: '0x00', desc: 'Windows TCP/IP stack with Window Auto-Tuning' },
    { os: 'Cisco IOS Router', defaultTtl: 255, windowSize: '4128', dfBit: 'Not Set (0)', tos: '0xC0', desc: 'Cisco router network OS with Precedence bits' },
    { os: 'Solaris 10 / 11', defaultTtl: 255, windowSize: '8760 / 32768', dfBit: 'Set (1)', tos: '0x00', desc: 'Enterprise Unix stack' }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <EyeOff className="w-5 h-5 text-indigo-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              IDS & Firewall Evasion Laboratory (CEH v13 Module 03)
            </h2>
            <ProvenanceBadge type="educational" label="MÔ PHỎNG GIÁO DỤC" />
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Bypass stateless packet filters, confuse stateful intrusion detection systems (IDS/IPS), and evade signature heuristics.
          </p>
        </div>

        {/* Sub-tabs navigation */}
        <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
          <button
            onClick={() => setActiveSubTab('generator')}
            className={`px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
              activeSubTab === 'generator' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Nmap Evasion Crafter
          </button>
          <button
            onClick={() => setActiveSubTab('fingerprinting')}
            className={`px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
              activeSubTab === 'fingerprinting' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            OS Fingerprint Criteria
          </button>
          <button
            onClick={() => setActiveSubTab('hping3')}
            className={`px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
              activeSubTab === 'hping3' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Hping3 Custom Packets
          </button>
          <button
            onClick={() => setActiveSubTab('matrix')}
            className={`px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer ${
              activeSubTab === 'matrix' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Evasion Technique Matrix
          </button>
        </div>
      </div>

      {/* SubTab 1: Nmap Evasion Crafter */}
      {activeSubTab === 'generator' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left 7 Cols: Interactive Controls */}
          <div className="lg:col-span-7 bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-5">
            <div className="border-b border-slate-100 pb-3">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-700">
                Evasion Technique Flag Configurator
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">Toggle flags to craft custom bypass signatures matching CEH Chapter 3 guidelines.</p>
            </div>

            {/* 1. Scan Technique */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700">Scan Engine Technique</label>
              <div className="grid grid-cols-3 gap-2 text-xs">
                {[
                  { id: '-sS', label: 'SYN Stealth (-sS)', desc: 'Half-open probe' },
                  { id: '-sT', label: 'TCP Connect (-sT)', desc: 'Full 3-way handshake' },
                  { id: '-sX', label: 'Xmas Tree (-sX)', desc: 'FIN, PSH, URG set' },
                  { id: '-sN', label: 'Null Scan (-sN)', desc: 'No flags set' },
                  { id: '-sF', label: 'FIN Scan (-sF)', desc: 'Only FIN set' },
                  { id: '-sA', label: 'ACK Probe (-sA)', desc: 'Firewall ruleset mapper' },
                ].map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setScanType(item.id)}
                    className={`p-2 rounded-lg border text-left cursor-pointer transition-all ${
                      scanType === item.id
                        ? 'border-blue-600 bg-blue-50/60 text-blue-900 font-semibold'
                        : 'border-slate-200 hover:border-slate-300 text-slate-700'
                    }`}
                  >
                    <div className="font-mono text-xs">{item.label}</div>
                    <div className="text-[10px] text-slate-400">{item.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* 2. Packet Fragmentation */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700">Packet Fragmentation & MTU Slicing</label>
              <div className="grid grid-cols-4 gap-2 text-xs">
                {[
                  { id: 'none', label: 'Disabled', desc: 'Standard IP datagram' },
                  { id: 'fragment', label: '-f (8-byte)', desc: 'Split header in 2 chunks' },
                  { id: 'mtu16', label: '--mtu 16', desc: '16-byte MTU offsets' },
                  { id: 'mtu24', label: '--mtu 24', desc: '24-byte MTU offsets' },
                ].map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setFragmentOption(item.id as any)}
                    className={`p-2 rounded-lg border text-left cursor-pointer transition-all ${
                      fragmentOption === item.id
                        ? 'border-blue-600 bg-blue-50/60 text-blue-900 font-semibold'
                        : 'border-slate-200 hover:border-slate-300 text-slate-700'
                    }`}
                  >
                    <div className="font-mono text-xs">{item.label}</div>
                    <div className="text-[10px] text-slate-400">{item.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* 3. Decoy & Source Port Manipulation */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Decoys */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700">IP Decoy Cloaking (-D)</span>
                  <input
                    type="checkbox"
                    checked={decoyMode}
                    onChange={(e) => setDecoyMode(e.target.checked)}
                    className="accent-blue-600 w-4 h-4 cursor-pointer"
                  />
                </div>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Floods target IDS log with fake source IPs to obscure your real origin address.
                </p>
                {decoyMode && (
                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-xs font-mono text-slate-600">Decoys: {decoyCount}</span>
                    <input
                      type="range"
                      min={2}
                      max={12}
                      value={decoyCount}
                      onChange={(e) => setDecoyCount(Number(e.target.value))}
                      className="flex-1 accent-blue-600 cursor-pointer"
                    />
                  </div>
                )}
              </div>

              {/* Source Port */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
                <span className="text-xs font-bold text-slate-700 block">Source Port Manipulation (-g)</span>
                <p className="text-[10px] text-slate-500 leading-tight">
                  Emits scan packets from well-known listening ports to bypass misconfigured ingress rules.
                </p>
                <div className="grid grid-cols-4 gap-1 text-[11px] font-mono">
                  {['none', '53', '88', '20'].map((p) => (
                    <button
                      key={p}
                      onClick={() => setSourcePortMode(p as any)}
                      className={`py-1 rounded border text-center cursor-pointer ${
                        sourcePortMode === p
                          ? 'bg-blue-600 text-white border-blue-600 font-bold'
                          : 'bg-white text-slate-700 border-slate-200'
                      }`}
                    >
                      {p === 'none' ? 'Off' : `:${p}`}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* 4. MAC Spoofing & Timing Engine */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Timing */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700">IDS Timing Template</label>
                <select
                  value={timingTemplate}
                  onChange={(e) => setTimingTemplate(e.target.value as any)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs font-mono text-slate-800"
                >
                  <option value="-T0">T0 (Paranoid - 5 min delay between probes)</option>
                  <option value="-T1">T1 (Sneaky - 15 sec delay for IDS evasion)</option>
                  <option value="-T2">T2 (Polite - Slows scan to minimize load)</option>
                  <option value="-T3">T3 (Normal - Default standard timing)</option>
                  <option value="-T4">T4 (Aggressive - Fast enterprise networks)</option>
                  <option value="-T5">T5 (Insane - Extremely fast / noisy)</option>
                </select>
              </div>

              {/* MAC Spoofing */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-700">MAC Address Hardware Spoofing</label>
                <select
                  value={spoofMac}
                  onChange={(e) => setSpoofMac(e.target.value as any)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs font-mono text-slate-800"
                >
                  <option value="none">Disabled (Real Hardware MAC)</option>
                  <option value="cisco">Cisco Systems OUI Prefix</option>
                  <option value="apple">Apple Inc. OUI Prefix</option>
                  <option value="dell">Dell Computer OUI Prefix</option>
                  <option value="random">Randomize Completely</option>
                </select>
              </div>
            </div>

            {/* 5. Checksum & Randomize Checkboxes */}
            <div className="flex flex-wrap gap-4 pt-1 text-xs">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={badChecksum}
                  onChange={(e) => setBadChecksum(e.target.checked)}
                  className="accent-blue-600 w-4 h-4 cursor-pointer"
                />
                <span className="text-slate-700 font-medium">Send Invalid TCP Checksum (--badsum)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={randomizeHosts}
                  onChange={(e) => setRandomizeHosts(e.target.checked)}
                  className="accent-blue-600 w-4 h-4 cursor-pointer"
                />
                <span className="text-slate-700 font-medium">Randomize Target Order (--randomize-hosts)</span>
              </label>
            </div>
          </div>

          {/* Right 5 Cols: Live Generated Command Terminal & Explanation */}
          <div className="lg:col-span-5 space-y-4">
            {/* Command Box */}
            <div className="bg-slate-900 text-slate-100 rounded-xl p-5 border border-slate-800 shadow-md">
              <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-mono font-bold text-slate-300">Generated Evasion Command</span>
                </div>
                <button
                  onClick={() => handleCopy(buildNmapCommand(), 'nmap-cmd')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1 bg-slate-800 px-2 py-1 rounded cursor-pointer transition-colors"
                >
                  {copiedId === 'nmap-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedId === 'nmap-cmd' ? 'Copied' : 'Copy'}
                </button>
              </div>

              <div className="bg-slate-950 p-3.5 rounded-lg font-mono text-xs text-emerald-400 leading-relaxed break-all border border-slate-800">
                # {buildNmapCommand()}
              </div>

              <div className="mt-4 space-y-2 text-[11px] text-slate-400">
                <div className="font-semibold text-slate-200">CEH v13 Evasion Mechanics:</div>
                <ul className="space-y-1.5 list-disc pl-4">
                  {fragmentOption !== 'none' && (
                    <li><strong className="text-blue-400">Fragmentation:</strong> IP header is split across multiple fragments so packet filters cannot inspect the full TCP port header in packet #1.</li>
                  )}
                  {decoyMode && (
                    <li><strong className="text-purple-400">Decoys:</strong> Target receives packets from {decoyCount} random IP addresses simultaneously with your probe, burying real source IP in logs.</li>
                  )}
                  {sourcePortMode !== 'none' && (
                    <li><strong className="text-amber-400">Source Port {sourcePortMode}:</strong> Many legacy firewalls allow inbound traffic if source port is 53 (DNS) or 20 (FTP Data).</li>
                  )}
                  {badChecksum && (
                    <li><strong className="text-rose-400">Bad Checksum:</strong> Real hosts drop invalid checksum packets silently. If a response is received, it came from a stateless NAT/Firewall proxy.</li>
                  )}
                </ul>
              </div>
            </div>

            {/* Packet Slicing Diagram */}
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-600" />
                Packet Fragmentation Inspection Breakdown
              </h4>
              <div className="space-y-2 font-mono text-[11px]">
                <div className="p-2 bg-blue-50 border border-blue-200 rounded text-blue-950 flex justify-between items-center">
                  <span>Fragment #1 (Offset 0)</span>
                  <span className="text-[10px] bg-blue-200 px-1.5 py-0.5 rounded font-bold">IP Header + First 8B of TCP</span>
                </div>
                <div className="p-2 bg-indigo-50 border border-indigo-200 rounded text-indigo-950 flex justify-between items-center">
                  <span>Fragment #2 (Offset 8)</span>
                  <span className="text-[10px] bg-indigo-200 px-1.5 py-0.5 rounded font-bold">Remaining TCP Header Flags</span>
                </div>
              </div>
              <p className="text-[11px] text-slate-500 mt-3 leading-relaxed">
                Unless the firewall reassembles IP fragments before forwarding (stateful inspection), the initial rule match cannot determine destination port or TCP flags.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SubTab 2: OS Fingerprinting Criteria Matrix */}
      {activeSubTab === 'fingerprinting' && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
              Operating System Discovery & Fingerprinting Matrix (CEH Table 3.2)
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              Stack fingerprinting examines standard default values for Time to Live (TTL), TCP Window Size, Don't Fragment (DF) bit, and Type of Service (TOS).
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-y border-slate-200 text-slate-500 font-mono text-[11px]">
                  <th className="py-3 px-4">Operating System</th>
                  <th className="py-3 px-4">Default IP TTL</th>
                  <th className="py-3 px-4">TCP Window Size</th>
                  <th className="py-3 px-4">DF (Don't Fragment)</th>
                  <th className="py-3 px-4">TOS Field</th>
                  <th className="py-3 px-4">Stack Signature Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {OS_FINGERPRINT_TABLE.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-800">{row.os}</td>
                    <td className="py-3 px-4 font-mono font-bold text-blue-700 bg-blue-50/40">{row.defaultTtl}</td>
                    <td className="py-3 px-4 font-mono text-slate-700">{row.windowSize}</td>
                    <td className="py-3 px-4 font-mono text-slate-700">{row.dfBit}</td>
                    <td className="py-3 px-4 font-mono text-slate-700">{row.tos}</td>
                    <td className="py-3 px-4 text-slate-600">{row.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs text-slate-600 space-y-2">
            <div className="font-bold text-slate-800">Passive Banner Grabbing via TCP Packets:</div>
            <p className="leading-relaxed">
              When capturing passive traffic using Wireshark or `tcpdump`, observe the initial SYN-ACK from the server. If TTL is ~64, the server is most likely Linux/BSD; if TTL is ~128, it is Windows Server; if TTL is ~255, it is a network appliance or Solaris daemon.
            </p>
          </div>
        </div>
      )}

      {/* SubTab 3: Hping3 Custom Packet Crafter */}
      {activeSubTab === 'hping3' && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
              Hping3 Custom Packet Crafter & SYN Prober (CEH Slide 84)
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              Assemble custom TCP/UDP/ICMP packets with customized header fields, sequence numbers, and payload sizes.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 text-slate-100 space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono font-bold text-amber-400">Custom Hping3 Command</span>
                <button
                  onClick={() => handleCopy(buildHping3Command(), 'hping-cmd')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1 bg-slate-800 px-2 py-1 rounded cursor-pointer"
                >
                  {copiedId === 'hping-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedId === 'hping-cmd' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-slate-950 p-3 rounded font-mono text-xs text-emerald-400 break-all border border-slate-800">
                # {buildHping3Command()}
              </div>
              <p className="text-[11px] text-slate-400">
                Sends 10 TCP SYN packets to port 80 with specified fragmentation and source port bypassing.
              </p>
            </div>

            <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 text-slate-100 space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono font-bold text-cyan-400">IP Spoofing & ICMP Timestamp</span>
                <button
                  onClick={() => handleCopy(`hping3 -1 ${host} --icmptype 13 -c 3`, 'icmp-cmd')}
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1 bg-slate-800 px-2 py-1 rounded cursor-pointer"
                >
                  {copiedId === 'icmp-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedId === 'icmp-cmd' ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="bg-slate-950 p-3 rounded font-mono text-xs text-cyan-400 break-all border border-slate-800">
                # hping3 -1 {host} --icmptype 13 -c 3
              </div>
              <p className="text-[11px] text-slate-400">
                Probes ICMP timestamp request (Type 13) to determine remote system time without standard ICMP echo echo-requests.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* SubTab 4: Technique Matrix */}
      {activeSubTab === 'matrix' && (
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">
            Firewall & IDS Evasion Methodology Matrix
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5">
              <div className="font-bold text-slate-800">1. Packet Fragmentation (`-f`, `--mtu`)</div>
              <p className="text-slate-600 leading-relaxed">
                Splits the 20-byte TCP header across multiple IP fragments (e.g. 8 bytes per chunk). Stateless firewalls fail to inspect port numbers on offset chunks.
              </p>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5">
              <div className="font-bold text-slate-800">2. Source Port Manipulation (`-g 53 / 88 / 20`)</div>
              <p className="text-slate-600 leading-relaxed">
                Exploits poorly designed firewall access-control lists (ACLs) that blindly trust traffic originating from DNS (53), Kerberos (88), or FTP Data (20).
              </p>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5">
              <div className="font-bold text-slate-800">3. Decoy Scanning (`-D RND:10,ME`)</div>
              <p className="text-slate-600 leading-relaxed">
                Blends genuine scan traffic with spoofed traffic from 10+ innocent third-party hosts so security operations center (SOC) analysts cannot isolate the real attacker.
              </p>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5">
              <div className="font-bold text-slate-800">4. Bad Checksum Probe (`--badsum`)</div>
              <p className="text-slate-600 leading-relaxed">
                Injects mathematically corrupt TCP checksums. Real end-hosts discard these packets, whereas misconfigured proxy firewalls respond, exposing their presence.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
