import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { WhoisModule } from './components/WhoisModule';
import { PortScannerModule } from './components/PortScannerModule';
import { ServerAuditModule } from './components/ServerAuditModule';
import { ExploitSandboxModule } from './components/ExploitSandboxModule';
import { EvasionLabModule } from './components/EvasionLabModule';
import { DDoSResilienceModule } from './components/DDoSResilienceModule';
import { AICopilotModule } from './components/AICopilotModule';
import { CEHKnowledgeBase } from './components/CEHKnowledgeBase';
import { ReportModule } from './components/ReportModule';
import { MalwareScannerModule } from './components/MalwareScannerModule';
import { AdminLogin } from './components/AdminLogin';
import { AdminDashboard } from './components/AdminDashboard';
import { FastSpeedtestModule } from './components/FastSpeedtestModule';
import { LanIntruderModule } from './components/LanIntruderModule';
import { GlobalThreatHeatmap } from './components/GlobalThreatHeatmap';
import { InternalNetworkReviewModule } from './components/InternalNetworkReviewModule';
import { WhoisRecord, DnsRecords, PortScanResult, WebAuditResult, StressTestResult, MalwareScanResult } from './types';
import { Terminal, Shield, Sparkles, Activity, Search, ChevronDown, ChevronUp, ShieldCheck, Award, Info, ChevronRight, Wrench, Globe, X, Copy, Check, ShieldAlert } from 'lucide-react';
import Markdown from 'react-markdown';
import { Toaster } from 'sonner';
import {
  notifyScanCompleted,
  notifyThreatDetected,
  notifySecuritySuccess,
  notifySecurityWarning,
  notifySecurityInfo
} from './utils/securityToast';

export default function App() {
  const [domain, setDomain] = useState('example.com');
  const [activeTab, setActiveTab] = useState('whois');
  const [isLoading, setIsLoading] = useState(false);
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [isTerminalCollapsed, setIsTerminalCollapsed] = useState(false);

  const [theme, setTheme] = useState<'light' | 'cyberpunk'>(() => {
    return (localStorage.getItem('sentinel_theme') as 'light' | 'cyberpunk') || 'light';
  });

  useEffect(() => {
    localStorage.setItem('sentinel_theme', theme);
    const root = document.documentElement;
    if (theme === 'cyberpunk') {
      root.classList.add('cyberpunk');
    } else {
      root.classList.remove('cyberpunk');
    }
  }, [theme]);

  const [isAdminLoggedIn, setIsAdminLoggedIn] = useState(false);
  const [showAdminLogin, setShowAdminLogin] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/status', { credentials: 'same-origin' })
      .then(async response => {
        if (!response.ok) throw new Error('Authentication service unavailable');
        return response.json();
      })
      .then(data => {
        if (cancelled) return;
        setIsAdminLoggedIn(Boolean(data.authenticated));
        setShowAdminLogin(!data.authenticated);
      })
      .catch(() => {
        if (!cancelled) setShowAdminLogin(true);
      });
    return () => { cancelled = true; };
  }, []);
  
  // Scan Data State
  const [whoisData, setWhoisData] = useState<WhoisRecord | null>(null);
  const [dnsData, setDnsData] = useState<{ domain: string; records: DnsRecords } | null>(null);
  const [auditData, setAuditData] = useState<WebAuditResult | null>(null);
  const [portData, setPortData] = useState<{
    host: string;
    ip: string;
    scannedPortsCount: number;
    openPortsCount: number;
    results: PortScanResult[];
  } | null>(null);
  const [ddosData, setDdosData] = useState<StressTestResult | null>(null);
  const [malwareData, setMalwareData] = useState<MalwareScanResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);

  // Terminal Live Logs
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[*] Sentinel OS v2.4 initialized.',
    '[*] CEH v13 Ethical Hacking & Security Assessment Suite ready.',
    '[*] Target set to example.com. Ready for reconnaissance & stress testing.'
  ]);

  const getTcvnStats = () => {
    const hasHighOrCritical = auditData?.vulnerabilities?.some(
      v => v.severity.toLowerCase() === 'critical' || v.severity.toLowerCase() === 'high'
    ) ?? false;

    const openPortsCount = portData?.openPortsCount ?? 0;

    const checks = [
      // TCVN 14423
      { id: '1', title: 'TCVN 14423 - Mục 5.1 (WHOIS Mapped)', passed: whoisData !== null },
      { id: '2', title: 'TCVN 14423 - Mục 5.2 (Web Configuration Audited)', passed: auditData !== null },
      { id: '3', title: 'TCVN 14423 - Mục 5.3 (No Critical or High Vulnerabilities)', passed: auditData !== null && !hasHighOrCritical },
      { id: '4', title: 'TCVN 14423 - Mục 5.4 (Target IPs Mapped)', passed: !!whoisData?.ipAddresses && whoisData.ipAddresses.length > 0 },
      // TCVN 14192-1
      { id: '5', title: 'TCVN 14192-1 - Mục 6.1 (Secure TLS v1.2/v1.3)', passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false },
      { id: '6', title: 'TCVN 14192-1 - Mục 6.2 (Active DNS NameServers)', passed: !!whoisData?.nameServers && whoisData.nameServers.length > 0 },
      { id: '7', title: 'TCVN 14192-1 - Mục 6.3 (Protected Banner Disclosure)', passed: auditData ? (!auditData.serverBanner?.toLowerCase().includes('apache/2.2') && !auditData.serverBanner?.toLowerCase().includes('outdated')) : false },
      // TCVN 14192-2
      { id: '8', title: 'TCVN 14192-2 - Mục 7.1 (Minimal Open Ports <= 3)', passed: portData !== null && openPortsCount <= 3 },
      { id: '9', title: 'TCVN 14192-2 - Mục 7.2 (DoS Resilience Level Passed)', passed: ddosData ? (ddosData.resilienceRating === 'Resilient' || ddosData.resilienceRating === 'Moderate') : false },
      { id: '10', title: 'TCVN 14192-2 - Mục 7.3 (Active WAF Perimeter)', passed: ddosData ? ddosData.wafDetected : false }
    ];

    const total = checks.length;
    const passed = checks.filter(c => c.passed).length;
    const score = Math.round((passed / total) * 100);

    return { score, passed, total, checks };
  };

  const getInternationalStats = () => {
    const hasHighOrCritical = auditData?.vulnerabilities?.some(
      v => v.severity.toLowerCase() === 'critical' || v.severity.toLowerCase() === 'high'
    ) ?? false;

    const openPortsCount = portData?.openPortsCount ?? 0;

    const owaspWstg = [
      { id: 'w1', title: 'OWASP WSTG - CRYP (Secure TLS Protocols)', passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false },
      { id: 'w2', title: 'OWASP WSTG - INFO (Banner Grabbing Control)', passed: auditData ? (!auditData.serverBanner?.toLowerCase().includes('apache/2.2') && !auditData.serverBanner?.toLowerCase().includes('outdated')) : false },
      { id: 'w3', title: 'OWASP WSTG - SESS (Clickjacking & nosniff headers)', passed: auditData ? (auditData.headers?.some(h => h.name.toLowerCase() === 'x-frame-options' && h.present) && auditData.headers?.some(h => h.name.toLowerCase() === 'x-content-type-options' && h.present)) : false }
    ];

    const owaspTop10 = [
      { id: 'o1', title: 'OWASP Top 10 - A02:2021 (Cryptographic Failures)', passed: auditData ? (auditData.tlsVersion === 'TLSv1.3' || auditData.tlsVersion === 'TLSv1.2') : false },
      { id: 'o2', title: 'OWASP Top 10 - A05:2021 (Security Misconfiguration)', passed: openPortsCount <= 3 && (auditData ? !auditData.serverBanner?.toLowerCase().includes('apache/2.2') : true) },
      { id: 'o3', title: 'OWASP Top 10 - A06:2021 (Vulnerable Components)', passed: auditData !== null && !hasHighOrCritical }
    ];

    const nist = [
      { id: 'n1', title: 'NIST SP 800-115 - 4.2 (Information Gathering)', passed: whoisData !== null },
      { id: 'n2', title: 'NIST SP 800-115 - 4.3 (Port Scanning & Enumeration)', passed: portData !== null },
      { id: 'n3', title: 'NIST SP 800-115 - 4.4 (Vulnerability Security Auditing)', passed: auditData !== null }
    ];

    const ptes = [
      { id: 'p1', title: 'PTES Framework - Phase 2 (Intelligence Gathering)', passed: !!whoisData?.nameServers && whoisData.nameServers.length > 0 },
      { id: 'p2', title: 'PTES Framework - Phase 4 (Vulnerability Analysis)', passed: auditData !== null && portData !== null },
      { id: 'p3', title: 'PTES Framework - Phase 5 (Resilience Threat Modeling)', passed: ddosData !== null }
    ];

    const all = [...owaspWstg, ...owaspTop10, ...nist, ...ptes];
    const total = all.length;
    const passed = all.filter(c => c.passed).length;
    const score = total > 0 ? Math.round((passed / total) * 100) : 0;

    return { score, passed, total, owaspWstg, owaspTop10, nist, ptes, all };
  };

  // Auto-Patch States & Remediators
  const [showPatchModal, setShowPatchModal] = useState(false);
  const [patchSuggestions, setPatchSuggestions] = useState<string | null>(null);
  const [isGeneratingPatches, setIsGeneratingPatches] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);

  const handleGeneratePatches = async (e?: React.MouseEvent) => {
    if (e) {
      e.stopPropagation(); // Avoid triggering navigation tab change when clicking the button inside the widget
    }
    setIsGeneratingPatches(true);
    setShowPatchModal(true);
    setPatchSuggestions(null);
    try {
      const tcvnStats = getTcvnStats();
      const intlStats = getInternationalStats();
      
      const failedChecks = [
        ...tcvnStats.checks.filter(c => !c.passed).map(c => c.title),
        ...intlStats.owaspWstg.filter(c => !c.passed).map(c => c.title),
        ...intlStats.owaspTop10.filter(c => !c.passed).map(c => c.title),
        ...intlStats.nist.filter(c => !c.passed).map(c => c.title),
        ...intlStats.ptes.filter(c => !c.passed).map(c => c.title)
      ];

      const res = await fetch('/api/ai-patch-suggestions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          failedChecks: failedChecks.length > 0 ? failedChecks : null,
          context: {
            tlsVersion: auditData?.tlsVersion,
            serverBanner: auditData?.serverBanner,
            openPortsCount: portData?.openPortsCount,
            wafDetected: ddosData?.wafDetected,
            resilienceRating: ddosData?.resilienceRating,
            vulnerabilitiesCount: auditData?.vulnerabilities?.length || 0
          }
        })
      });

      if (!res.ok) {
        throw new Error('Yêu cầu tạo kịch bản vá tự động từ Sentinel AI không thành công');
      }

      const data = await res.json();
      setPatchSuggestions(data.suggestions);
      notifySecuritySuccess(
        'Đã Tạo Kịch Bản Vá Cấu Hình An Ninh!',
        'Sentinel AI đã sinh các lệnh hardening Nginx/Apache và cấu hình sysctl.'
      );
    } catch (error: any) {
      console.error(error);
      setPatchSuggestions(`### ❌ Lỗi tạo kịch bản vá cấu hình\n\nKhông thể kết nối đến máy chủ AI hoặc dịch vụ đang bận. Vui lòng thử lại sau giây lát.\n\nChi tiết lỗi: ${error.message}`);
      notifySecurityWarning('Lỗi tạo kịch bản vá tự động', error.message);
    } finally {
      setIsGeneratingPatches(false);
    }
  };

  const handleCopyPatchesToClipboard = () => {
    if (patchSuggestions) {
      navigator.clipboard.writeText(patchSuggestions);
      setCopiedPatch(true);
      notifySecuritySuccess('Đã sao chép kịch bản vá cấu hình vào Clipboard!');
      setTimeout(() => setCopiedPatch(false), 2000);
    }
  };

  const [consoleCommand, setConsoleCommand] = useState('');

  const handleConsoleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const commands = ['help', 'clear', 'status', 'scan', 'vulnerabilities', 'ports', 'ddos', 'ping', 'nmap'];
      const currentInput = consoleCommand.trim().toLowerCase();

      if (!currentInput) {
        addLog(`[AUTOCOMPLETE] Available commands: ${commands.join(', ')}`);
        return;
      }

      const matches = commands.filter(cmd => cmd.startsWith(currentInput));
      if (matches.length === 1) {
        setConsoleCommand(matches[0]);
      } else if (matches.length > 1) {
        addLog(`root@sentinel:~# ${consoleCommand} <TAB>`);
        addLog(`[AUTOCOMPLETE] Matches: ${matches.join(', ')}`);
        // Find longest common prefix of matches
        let commonPrefix = currentInput;
        let index = currentInput.length;
        while (true) {
          const nextChar = matches[0][index];
          if (!nextChar) break;
          const allHaveChar = matches.every(m => m[index] === nextChar);
          if (allHaveChar) {
            commonPrefix += nextChar;
            index++;
          } else {
            break;
          }
        }
        setConsoleCommand(commonPrefix);
      } else {
        addLog(`[AUTOCOMPLETE] No matching commands found for "${currentInput}"`);
      }
    }
  };

  const addLog = (log: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setTerminalLogs(prev => [...prev.slice(-40), `[${timestamp}] ${log}`]);
  };

  const handleConsoleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cmdClean = consoleCommand.trim().toLowerCase();
    if (!cmdClean) return;

    // Log the input command like a real terminal
    setTerminalLogs(prev => [...prev, `root@sentinel:~# ${consoleCommand}`]);
    setConsoleCommand('');

    const parts = cmdClean.split(/\s+/);
    const mainCmd = parts[0];

    switch (mainCmd) {
      case 'clear':
        setTerminalLogs(['[*] Console log buffer cleared by security operator.']);
        break;

      case 'help':
        setTerminalLogs(prev => [
          ...prev,
          '-- SENTINEL OS PSEUDO-CONSOLE UTILITY GUIDE --',
          'Available commands for interacting with the current security session:',
          '  help             Display this available instruction index.',
          '  clear            Purge the terminal log history.',
          '  status           Print current recon state, targets, and caching.',
          '  scan             Manually run a full pentest recon sequence.',
          '  vulnerabilities  List details of discovered security issues.',
          '  ports            Display all mapped open TCP/UDP ports.',
          '  ddos             Show DDoS benchmarking metrics & resilience.',
          '  ping <host>      Show ICMP availability without fake measurements.',
          '  nmap <host>      Show measured backend TCP port scan results.',
          '----------------------------------------------'
        ]);
        break;

      case 'status':
        setTerminalLogs(prev => [
          ...prev,
          `[STATUS] Target Domain: ${domain}`,
          `[STATUS] Active Module: ${activeTab.toUpperCase()}`,
          `[STATUS] Local Caching: ${hasSavedSession ? 'Active Session Restored' : 'No Cached Payload'}`,
          `[STATUS] Scanned State: ${whoisData ? 'Completed' : 'Pending Scan Run'}`,
          `[STATUS] System Load: Nominal | CPU Threads: 8 | Entropy: Stable`
        ]);
        break;

      case 'scan':
        setTerminalLogs(prev => [...prev, '[SYSTEM] Manual console trigger detected: Starting full pentest...']);
        handleRunFullAudit();
        break;

      case 'vulnerabilities':
        if (auditData && auditData.vulnerabilities && auditData.vulnerabilities.length > 0) {
          setTerminalLogs(prev => [
            ...prev,
            `[AUDIT] Discovered ${auditData.vulnerabilities.length} active vulnerabilities for ${domain}:`,
            ...auditData.vulnerabilities.map((v: any) => `  -> [${v.severity}] ${v.name} - ${v.description.substring(0, 80)}...`)
          ]);
        } else {
          setTerminalLogs(prev => [...prev, `[WARN] No vulnerability records found for ${domain}. Type 'scan' to run audit.`]);
        }
        break;

      case 'ports':
        if (portData && portData.results && portData.results.length > 0) {
          const openPorts = portData.results.filter((p: any) => p.status === 'Open');
          setTerminalLogs(prev => [
            ...prev,
            `[PORTS] Port scan status for host ${portData.ip || domain}:`,
            `  - Total ports scanned: ${portData.scannedPortsCount}`,
            `  - Open TCP/UDP ports: ${openPorts.length}`,
            ...openPorts.map((p: any) => `    -> Port ${p.port}/${p.protocol}: ${p.service} (${p.risk} risk)`)
          ]);
        } else {
          setTerminalLogs(prev => [...prev, `[WARN] No port scanner reports found. Type 'scan' to scan target ports.`]);
        }
        break;

      case 'ddos':
        if (ddosData) {
          setTerminalLogs(prev => [
            ...prev,
            `[DDOS] Resilience Benchmark Report for ${domain}:`,
            `  - Simulated Requests: ${ddosData.totalRequests}`,
            `  - Successful Requests: ${ddosData.successfulRequests}`,
            `  - Failed Requests: ${ddosData.failedRequests}`,
            `  - P95 Response Latency: ${ddosData.p95LatencyMs}ms`,
            `  - Resilience Rating: ${ddosData.resilienceRating} (${ddosData.wafDetected ? 'WAF Protected' : 'No WAF detected'})`
          ]);
        } else {
          setTerminalLogs(prev => [...prev, `[WARN] No stress benchmark history is active. Run a scan or open the DoS tab.`]);
        }
        break;

      case 'ping': {
        const pingTarget = parts[1] || domain;
        setTerminalLogs(prev => [
          ...prev,
          `[INFO] Chưa có phép đo ICMP thực tế cho ${pingTarget}.`,
          '[INFO] ICMP ping cần LAN Agent hoặc trình đo trên backend được cấp quyền. Không hiển thị số liệu mô phỏng.'
        ]);
        break;
      }

      case 'nmap': {
        const nmapTarget = parts[1] || domain;
        if (nmapTarget !== domain) {
          setTerminalLogs(prev => [...prev, `[WARN] Kết quả quét hiện tại chỉ thuộc mục tiêu ${domain}; không có dữ liệu cho ${nmapTarget}.`]);
          break;
        }
        if (!portData?.results) {
          setTerminalLogs(prev => [...prev, `[WARN] Chưa có kết quả quét cổng cho ${nmapTarget}. Hãy chạy scan trước.`]);
          break;
        }
        const openPorts = portData.results.filter((p: any) => p.status === 'Open' || p.status === 'open');
        setTerminalLogs(prev => [
          ...prev,
          `[PORT SCAN] Kết quả TCP từ backend cho ${nmapTarget} (không phải Nmap):`,
          `Đã kiểm tra: ${portData.scannedPortsCount ?? portData.results.length}; mở: ${openPorts.length}`,
          'PORT     STATE SERVICE',
          ...openPorts.map((p: any) => `${p.port}/${p.protocol || 'tcp'} open ${p.service || 'unknown'}`),
          '[INFO] Không suy diễn rDNS hoặc OS nếu không có dữ liệu đo.'
        ]);
        break;
      }

      default:
        setTerminalLogs(prev => [
          ...prev,
          `[ERROR] Command '${mainCmd}' is not recognized as an internal instruction.`,
          `        Type 'help' to review the index of operational commands.`
        ]);
        break;
    }
  };

  // 1. Fetch WHOIS & DNS
  const fetchWhois = async (target: string) => {
    addLog(`[WHOIS] Querying RDAP & registry for ${target}...`);
    try {
      const [whoisRes, dnsRes] = await Promise.all([
        fetch('/api/whois', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: target })
        }),
        fetch('/api/dns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: target })
        })
      ]);

      if (whoisRes.ok) {
        const wData = await whoisRes.json();
        setWhoisData(wData);
        addLog(`[WHOIS] Registrar identified: ${wData.registrar || 'ICANN Accredited'}`);
      }
      if (dnsRes.ok) {
        const dData = await dnsRes.json();
        setDnsData(dData);
        addLog(`[DNS] Resolved A/MX/TXT/NS zone records successfully.`);
      }

      notifyScanCompleted({
        module: 'WHOIS & DNS RECON',
        title: `Thu thập danh tính & DNS hoàn bách cho ${target}`,
        summary: `Đã truy vấn máy chủ tên miền gốc RDAP và lập bản đồ bản ghi A, MX, TXT, NS.`,
        target,
        actionTab: 'whois',
        onAction: () => setActiveTab('whois')
      });
    } catch (e: any) {
      addLog(`[ERROR] WHOIS query failed: ${e.message}`);
    }
  };

  // 2. Fetch Web Audit & Security Headers
  const fetchWebAudit = async (target: string) => {
    addLog(`[AUDIT] Inspecting HTTP response headers, SSL cert & robots.txt on https://${target}...`);
    try {
      const res = await fetch('/api/web-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: target })
      });
      if (res.ok) {
        const aData: WebAuditResult = await res.json();
        setAuditData(aData);
        addLog(`[AUDIT] Server Banner: ${aData.serverBanner} | Security Score: ${aData.securityScore}/100 (${aData.securityGrade})`);

        // Check for severe vulnerabilities
        if (aData.vulnerabilities && aData.vulnerabilities.length > 0) {
          const criticals = aData.vulnerabilities.filter(v => v.severity === 'Critical' || v.severity === 'High');
          if (criticals.length > 0) {
            criticals.slice(0, 2).forEach(v => {
              notifyThreatDetected({
                title: `Lỗ hổng ${v.severity.toUpperCase()}: ${v.title}`,
                description: `${v.description} (${v.category} • CEH: ${v.cehModule})`,
                level: v.severity === 'Critical' ? 'critical' : 'high',
                cveId: v.id,
                host: target,
                actionTab: 'audit',
                onAction: () => setActiveTab('audit')
              });
            });
          }
        }

        notifyScanCompleted({
          module: 'WEB SERVER AUDIT',
          title: `Đánh giá an ninh Web hoàn tất (${aData.securityScore}/100 - Hạng ${aData.securityGrade})`,
          summary: `Máy chủ: ${aData.serverBanner || 'N/A'} | TLS: ${aData.tlsVersion} | Đã kiểm tra tiêu chuẩn TCVN & OWASP.`,
          target,
          hasThreats: (aData.vulnerabilities?.length || 0) > 0,
          actionTab: 'audit',
          onAction: () => setActiveTab('audit')
        });
      }
    } catch (e: any) {
      addLog(`[ERROR] Web audit failed: ${e.message}`);
    }
  };

  // 3. Fetch Port Scan
  const fetchPortScan = async (target: string, customPorts?: number[]) => {
    addLog(`[PORT SCAN] Initiating TCP port discovery on target host...`);
    try {
      const res = await fetch('/api/port-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: target, ports: customPorts })
      });
      if (res.ok) {
        const pData = await res.json();
        setPortData(pData);
        addLog(`[PORT SCAN] Discovery complete: ${pData.openPortsCount} open listening ports detected.`);

        // Flag suspicious ports
        const riskyPorts = pData.results?.filter((p: any) => p.status === 'Open' && [21, 23, 445, 3389, 1433, 3306].includes(p.port)) || [];
        if (riskyPorts.length > 0) {
          notifyThreatDetected({
            title: `Phát hiện ${riskyPorts.length} cổng dịch vụ nhạy cảm đang mở công khai`,
            description: `Các cổng [${riskyPorts.map((p: any) => `${p.port}/${p.service}`).join(', ')}] mở trực tiếp ra ngoài Internet có nguy cơ bị brute-force.`,
            level: 'high',
            host: target,
            actionTab: 'ports',
            onAction: () => setActiveTab('ports')
          });
        }

        notifyScanCompleted({
          module: 'PORT SCANNER',
          title: `Quét cổng hoàn tất: Phát hiện ${pData.openPortsCount} cổng TCP đang mở`,
          summary: `Thời gian quét: ${pData.scanDurationMs}ms. Đã phân loại dịch vụ và phiên bản banner.`,
          target,
          hasThreats: riskyPorts.length > 0,
          actionTab: 'ports',
          onAction: () => setActiveTab('ports')
        });
      }
    } catch (e: any) {
      addLog(`[ERROR] Port scan failed: ${e.message}`);
    }
  };

  // 4. Fetch Malware, Trojan & Link Security Inspection
  const fetchMalwareScan = async (target: string) => {
    addLog(`[MALWARE CHECK] Inspecting ${target} for hidden SEO links, junk outlinks, web shells & Trojan beacons...`);
    try {
      const res = await fetch('/api/malware-link-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: target })
      });
      if (res.ok) {
        const mData: MalwareScanResult = await res.json();
        setMalwareData(mData);
        addLog(`[MALWARE CHECK] Analysis complete: Status ${mData.status} (${mData.cleanlinessScore}/100) - ${mData.totalThreatsCount} threat(s) flagged.`);

        if (mData.totalThreatsCount > 0 || mData.cleanlinessScore < 80) {
          notifyThreatDetected({
            title: `Cảnh báo Mã Độc & Liên Kết Rác: ${mData.totalThreatsCount} mối đe dọa`,
            description: `Điểm sạch mã nguồn: ${mData.cleanlinessScore}/100. Đã phát hiện dấu hiệu spam link, script ẩn hoặc webshell tiềm ẩn.`,
            level: mData.cleanlinessScore < 60 ? 'critical' : 'high',
            host: target,
            actionTab: 'malware',
            onAction: () => setActiveTab('malware')
          });
        }

        notifyScanCompleted({
          module: 'MALWARE INSPECTOR',
          title: `Quét mã độc hoàn tất (${mData.cleanlinessScore}/100 - ${mData.status})`,
          summary: `Phát hiện ${mData.totalThreatsCount} đe dọa (${mData.hiddenLinks.length} liên kết ẩn, ${mData.junkLinks.length} liên kết rác, ${mData.virusSignatures.length + mData.trojanThreats.length} mã độc).`,
          target,
          hasThreats: mData.totalThreatsCount > 0,
          actionTab: 'malware',
          onAction: () => setActiveTab('malware')
        });
      }
    } catch (e: any) {
      addLog(`[ERROR] Malware check failed: ${e.message}`);
    }
  };

  // 5. Fetch DDoS & Stress Test
  const handleRunStressTest = async (concurrency: number, duration: number) => {
    if (!domain) return;
    setIsLoading(true);
    addLog(`[STRESS TEST] Launching HTTP concurrency stress benchmark (Workers: ${concurrency}, Duration: ${duration}s)...`);
    try {
      const res = await fetch('/api/ddos-stress-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: domain,
          concurrency,
          durationSeconds: duration
        })
      });
      if (res.ok) {
        const dData: StressTestResult = await res.json();
        setDdosData(dData);
        addLog(`[STRESS TEST] Completed: ${dData.totalRequests} reqs sent @ ${dData.requestsPerSecond} req/s (p50: ${dData.p50LatencyMs}ms, Rating: ${dData.resilienceRating}).`);

        if (dData.resilienceRating === 'Vulnerable' || (dData.failedRequests || 0) > (dData.totalRequests || 1) * 0.3) {
          notifyThreatDetected({
            title: `Khả năng chịu tải DDoS kém: Trạng thái ${dData.resilienceRating}`,
            description: `Hệ thống phản hồi chậm hoặc lỗi với tỉ lệ thất bại cao dưới áp lực ${concurrency} luồng đồng thời.`,
            level: 'high',
            host: domain,
            actionTab: 'ddos',
            onAction: () => setActiveTab('ddos')
          });
        }

        notifyScanCompleted({
          module: 'DDOS BENCHMARK',
          title: `Kiểm tra DoS hoàn tất: ${dData.requestsPerSecond} req/s (Độ trễ ${dData.p50LatencyMs}ms)`,
          summary: `Độ bền bỉ: ${dData.resilienceRating}. Đã gửi tổng cộng ${dData.totalRequests} yêu cầu HTTP.`,
          target: domain,
          hasThreats: dData.resilienceRating === 'Vulnerable',
          actionTab: 'ddos',
          onAction: () => setActiveTab('ddos')
        });
      }
    } catch (e: any) {
      addLog(`[ERROR] Stress benchmark failed: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // 6. Generate AI Comprehensive Assessment
  const handleGenerateAiReport = async () => {
    if (!domain || isAiGenerating) return;
    setIsAiGenerating(true);
    addLog(`[AI ENGINE] Formulating comprehensive Penetration Testing Report via Gemini 3.7 Flash...`);
    try {
      const res = await fetch('/api/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          reconData: { whois: whoisData, dns: dnsData },
          auditData,
          portScanData: portData,
          ddosData
        })
      });
      if (res.ok) {
        const data = await res.json();
        setAiAnalysis(data.analysis);
        addLog(`[AI ENGINE] Penetration test report compiled successfully.`);
        setActiveTab('report');
        notifySecuritySuccess(
          'Báo Cáo AI Pentest Đã Sẵn Sàng!',
          'Gemini 3.7 Flash đã tổng hợp đầy đủ đánh giá an ninh, rủi ro và khuyến nghị khắc phục.'
        );
      }
    } catch (e: any) {
      addLog(`[ERROR] AI analysis failed: ${e.message}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  // Full Suite Audit Trigger
  const handleRunFullAudit = async () => {
    if (!domain.trim()) return;
    setIsLoading(true);
    addLog(`[AUDIT] Starting full pentest pipeline on target: ${domain}...`);

    notifySecurityInfo(
      `Bắt đầu quy trình Pentest toàn diện trên ${domain}`,
      'Đang kích hoạt đồng thời Whois Recon, Web Audit, Port Scan, Malware & DoS Benchmark...'
    );

    await Promise.all([
      fetchWhois(domain),
      fetchWebAudit(domain),
      fetchPortScan(domain),
      fetchMalwareScan(domain)
    ]);

    // Also run baseline stress test
    await handleRunStressTest(4, 3);

    setIsLoading(false);
    addLog(`[AUDIT] Full pentest reconnaissance and benchmark finished.`);

    notifyScanCompleted({
      module: 'FULL PENTEST SUITE',
      title: `Hoàn tất toàn bộ quy trình kiểm thử xâm nhập mục tiêu ${domain}`,
      summary: `Tất cả các module trinh sát, dò quét cổng, phân tích web và kiểm tra DoS đã hoàn tất.`,
      target: domain,
      actionTab: 'report',
      onAction: () => setActiveTab('report')
    });
  };

  const [hasSavedSession, setHasSavedSession] = useState<boolean>(() => {
    return localStorage.getItem('sentinel_session_v2') !== null;
  });

  const handleSaveSession = () => {
    const sessionData = {
      domain,
      whoisData,
      dnsData,
      auditData,
      portData,
      ddosData,
      malwareData,
      aiAnalysis,
      terminalLogs,
      activeTab,
      timestamp: new Date().toISOString()
    };
    localStorage.setItem('sentinel_session_v2', JSON.stringify(sessionData));
    setHasSavedSession(true);
    addLog('[SYSTEM] Saved current pentest session & terminal logs to local storage.');
    notifySecuritySuccess(
      'Đã Lưu Phiên Kiểm Thử An Ninh!',
      'Toàn bộ kết quả scan, log terminal và phân tích AI đã được lưu trữ an toàn.'
    );
  };

  const handleClearSession = () => {
    localStorage.removeItem('sentinel_session_v2');
    setHasSavedSession(false);
    addLog('[SYSTEM] Cleared saved pentest session from local storage.');
    notifySecurityInfo('Đã Xóa Dữ Liệu Phiên', 'Bộ nhớ đệm session cục bộ đã được dọn sạch.');
  };

  // Load initial scan on mount or restore previous session
  useEffect(() => {
    const saved = localStorage.getItem('sentinel_session_v2');
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.domain) setDomain(data.domain);
        if (data.whoisData) setWhoisData(data.whoisData);
        if (data.dnsData) setDnsData(data.dnsData);
        if (data.auditData) setAuditData(data.auditData);
        if (data.portData) setPortData(data.portData);
        if (data.ddosData) setDdosData(data.ddosData);
        if (data.malwareData) setMalwareData(data.malwareData);
        if (data.aiAnalysis) setAiAnalysis(data.aiAnalysis);
        if (data.terminalLogs) setTerminalLogs(data.terminalLogs);
        if (data.activeTab) setActiveTab(data.activeTab);

        const timeStr = data.timestamp ? new Date(data.timestamp).toLocaleString() : 'previous session';
        const timestamp = new Date().toLocaleTimeString();
        setTerminalLogs(prev => [
          ...prev,
          `[${timestamp}] [*] RESTORED: Loaded pentest session from ${timeStr} successfully.`
        ]);
      } catch (err) {
        console.error('Failed to parse saved session:', err);
        handleRunFullAudit();
      }
    } else {
      handleRunFullAudit();
    }
  }, []);

  return (
    <div className="flex flex-col min-h-screen bg-slate-50 text-slate-900 font-sans antialiased selection:bg-blue-600 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        domain={domain}
        setDomain={setDomain}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRunFullAudit={handleRunFullAudit}
        isLoading={isLoading}
        theme={theme}
        setTheme={setTheme}
        onSaveSession={handleSaveSession}
        onClearSession={handleClearSession}
        hasSavedSession={hasSavedSession}
        onAdminLoginClick={() => setShowAdminLogin(true)}
      />

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 lg:p-10 space-y-10">
        {/* TCVN & International Live Regulatory Compliance Score Dashboard Widget */}
        {(() => {
          const tcvnStats = getTcvnStats();
          const intlStats = getInternationalStats();
          return (
            <div 
              onClick={() => setActiveTab('report')}
              className="bg-white hover:bg-slate-50/50 rounded-2xl border border-slate-200 p-6 sm:p-8 shadow-sm hover:shadow-md transition-all duration-300 cursor-pointer group hover:border-indigo-200 relative overflow-hidden"
            >
              {/* Subtle top decoration */}
              <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 via-indigo-500 to-blue-500"></div>

              <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-8">
                {/* Score Circular/Progress Badge & Target Info */}
                <div className="flex items-start gap-5">
                  <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-slate-50 border border-slate-100 shrink-0 mt-1">
                    <ShieldCheck className="w-8 h-8 text-indigo-600 group-hover:scale-110 transition-transform" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-indigo-700 bg-indigo-50 px-3 py-1 rounded-full border border-indigo-100">
                        TCVN & INTERNATIONAL COMPLIANCE
                      </span>
                      {tcvnStats.score === 100 && intlStats.score === 100 ? (
                        <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 px-3 py-1 rounded-full flex items-center gap-1.5 border border-emerald-100">
                          <Award className="w-3 h-3" /> Đạt Toàn Diện
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold text-slate-500 bg-slate-100 px-3 py-1 rounded-full border border-slate-200">
                          Live Auditing
                        </span>
                      )}
                    </div>
                    <h3 className="text-lg font-black text-slate-900 mt-2 flex items-center gap-2">
                      Chỉ Số Tuân Thủ Quy Chuẩn Bảo Mật Quốc Gia & Quốc Tế
                      <ChevronRight className="w-4 h-4 text-slate-400 group-hover:translate-x-1.5 transition-transform" />
                    </h3>
                    <p className="text-sm text-slate-600 mt-1 max-w-2xl">
                      Đối chiếu trực tiếp mục tiêu <span className="font-mono text-slate-800 font-bold bg-slate-100 px-1.5 py-0.5 rounded">{domain}</span> với các quy chuẩn an toàn mạng của Việt Nam và các bộ chuẩn an ninh hàng đầu thế giới.
                    </p>
                  </div>
                </div>

                {/* Score Metrics and Action Button */}
                <div className="flex flex-wrap items-center gap-4 xl:justify-end xl:text-right shrink-0">
                  {/* TCVN Score */}
                  <div className="bg-emerald-50/50 px-5 py-3 rounded-xl border border-emerald-100 min-w-[150px]">
                    <span className="text-[10px] text-emerald-800 uppercase tracking-widest block font-bold font-mono">Tỷ lệ TCVN đạt</span>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className="text-2xl font-black text-emerald-600">{tcvnStats.score}%</span>
                      <span className="text-[11px] font-semibold text-slate-500">({tcvnStats.passed}/{tcvnStats.total})</span>
                    </div>
                  </div>

                  {/* International Score */}
                  <div className="bg-indigo-50/50 px-5 py-3 rounded-xl border border-indigo-100 min-w-[150px]">
                    <span className="text-[10px] text-indigo-800 uppercase tracking-widest block font-bold font-mono">Tỷ lệ Quốc tế đạt</span>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className="text-2xl font-black text-indigo-600">{intlStats.score}%</span>
                      <span className="text-[11px] font-semibold text-slate-500">({intlStats.passed}/{intlStats.total})</span>
                    </div>
                  </div>

                  {/* AI Auto-Patch Trigger Button */}
                  <button
                    onClick={handleGeneratePatches}
                    className="px-6 py-4 bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 text-white rounded-xl flex items-center gap-2 font-bold transition-all text-sm shadow-sm hover:shadow-lg cursor-pointer shrink-0 z-10 hover:scale-[1.02]"
                  >
                    <Wrench className="w-4 h-4" />
                    Gợi Ý Vá Cấu Hình AI
                  </button>
                </div>
              </div>

              {/* Substandards Status Badges Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 mt-4 pt-4 border-t border-slate-100 text-[10px]">
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">TCVN 14423</span>
                  <strong className="text-slate-800 mt-1">
                    {tcvnStats.checks.slice(0, 4).filter(c => c.passed).length}/4 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">TCVN 14192-1</span>
                  <strong className="text-slate-800 mt-1">
                    {tcvnStats.checks.slice(4, 7).filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">TCVN 14192-2</span>
                  <strong className="text-slate-800 mt-1">
                    {tcvnStats.checks.slice(7, 10).filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">OWASP WSTG</span>
                  <strong className="text-indigo-800 mt-1">
                    {intlStats.owaspWstg.filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">OWASP Top 10</span>
                  <strong className="text-indigo-800 mt-1">
                    {intlStats.owaspTop10.filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">NIST 800-115</span>
                  <strong className="text-indigo-800 mt-1">
                    {intlStats.nist.filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
                <div className="bg-slate-50/60 p-2 rounded-lg flex flex-col justify-between border border-slate-100">
                  <span className="text-slate-400 uppercase tracking-wider block font-mono">PTES Standard</span>
                  <strong className="text-indigo-800 mt-1">
                    {intlStats.ptes.filter(c => c.passed).length}/3 Đạt
                  </strong>
                </div>
              </div>
            </div>
          );
        })()}

        {/* Auto-Patch Suggestions Modal */}
        {showPatchModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs transition-opacity duration-300 no-print">
            <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-200">
              {/* Modal Header */}
              <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50">
                <div className="flex items-center gap-2">
                  <Wrench className="w-5 h-5 text-indigo-600 animate-pulse" />
                  <div>
                    <h3 className="text-sm font-black text-slate-800 uppercase tracking-tight">Kịch Bản Tự Động Vá Cấu Hình (AI Auto-Patch Suggestions)</h3>
                    <p className="text-[11px] text-slate-500">Sentinel OS AI Hardening Engine • Vá lỗi bảo mật dựa trên TCVN & OWASP</p>
                  </div>
                </div>
                <button 
                  onClick={() => setShowPatchModal(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {isGeneratingPatches ? (
                  <div className="flex flex-col items-center justify-center py-16 space-y-4">
                    <div className="relative">
                      <div className="w-12 h-12 rounded-full border-4 border-indigo-100 border-t-indigo-600 animate-spin"></div>
                      <Sparkles className="w-5 h-5 text-indigo-500 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-bounce" />
                    </div>
                    <div className="text-center">
                      <p className="text-xs font-bold text-slate-800">Đang phân tích các lỗi bảo mật...</p>
                      <p className="text-[11px] text-slate-500 mt-1 max-w-md">Sentinel AI đang tham chiếu tài liệu TCVN 14192/14423 & OWASP Top 10 để soạn thảo các kịch bản vá bảo mật và hệ thống tường lửa cho bạn.</p>
                    </div>
                  </div>
                ) : patchSuggestions ? (
                  <div className="space-y-4">
                    <div className="bg-amber-50 border border-amber-200 text-amber-800 rounded-lg p-3 text-[11px] flex items-start gap-2">
                      <ShieldAlert className="w-4.5 h-4.5 shrink-0 mt-0.5 text-amber-600" />
                      <div>
                        <strong>Khuyến cáo an toàn:</strong> Kịch bản vá này được tạo tự động bởi AI dựa trên kết quả rà quét thực tế. Hãy kiểm tra kỹ trên môi trường thử nghiệm (Staging/Testing) trước khi triển khai trực tiếp vào hệ thống vận hành.
                      </div>
                    </div>
                    <div className="prose prose-sm max-w-none text-slate-800 bg-slate-50 rounded-xl p-5 overflow-auto max-h-[45vh] border border-slate-200">
                      <Markdown>{patchSuggestions}</Markdown>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-12 text-slate-400 text-xs">
                    Không có dữ liệu kịch bản vá cấu hình nào.
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="px-6 py-4 border-t border-slate-100 flex items-center justify-between bg-slate-50">
                <div className="text-[10px] text-slate-400 hidden sm:block">
                  Nhấn <strong>Sao chép</strong> để lấy toàn bộ kịch bản vá và áp dụng cho hệ điều hành/máy chủ của bạn.
                </div>
                <div className="flex items-center gap-2 ml-auto">
                  <button
                    onClick={() => setShowPatchModal(false)}
                    className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer"
                  >
                    Đóng
                  </button>
                  {patchSuggestions && !isGeneratingPatches && (
                    <button
                      onClick={handleCopyPatchesToClipboard}
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-lg transition-colors flex items-center gap-1.5 text-xs cursor-pointer shadow-xs"
                    >
                      {copiedPatch ? (
                        <>
                          <Check className="w-3.5 h-3.5" /> Đã Sao Chép
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" /> Sao Chép Kịch Bản
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
        
        {/* Admin Login Modal */}
        {showAdminLogin && (
          <AdminLogin 
            onLogin={() => {
              setIsAdminLoggedIn(true);
              setShowAdminLogin(false);
              setActiveTab('admin');
            }}
            onClose={() => setShowAdminLogin(false)}
          />
        )}

        {/* Active Tab View */}
        {activeTab === 'network-review' && (
          <InternalNetworkReviewModule theme={theme} />
        )}

        {activeTab === 'speedtest' && (
          <FastSpeedtestModule theme={theme} />
        )}

        {activeTab === 'lan-intruder' && (
          <LanIntruderModule theme={theme} />
        )}

        {activeTab === 'threat-map' && (
          <GlobalThreatHeatmap targetDomain={domain} theme={theme} />
        )}

        {activeTab === 'admin' && isAdminLoggedIn && (
           <AdminDashboard logs={terminalLogs} targetDomain={domain} />
        )}

        {activeTab === 'whois' && (
          <WhoisModule
            whoisData={whoisData}
            dnsData={dnsData}
            isLoading={isLoading}
            onRefresh={() => fetchWhois(domain)}
            domain={domain}
          />
        )}

        {activeTab === 'ports' && (
          <PortScannerModule
            portData={portData}
            isLoading={isLoading}
            onScanPorts={(customPorts?: number[]) => fetchPortScan(domain, customPorts)}
            domain={domain}
          />
        )}

        {activeTab === 'audit' && (
          <ServerAuditModule
            auditData={auditData}
            isLoading={isLoading}
            onRunAudit={() => fetchWebAudit(domain)}
            domain={domain}
            theme={theme}
          />
        )}

        {activeTab === 'malware' && (
          <MalwareScannerModule
            domain={domain}
            malwareData={malwareData}
            isLoading={isLoading}
            onRunScan={() => fetchMalwareScan(domain)}
            theme={theme}
          />
        )}

        {activeTab === 'sandbox' && (
          <ExploitSandboxModule
            targetDomain={domain}
          />
        )}

        {activeTab === 'evasion' && (
          <EvasionLabModule
            targetDomain={domain}
          />
        )}

        {activeTab === 'ddos' && (
          <DDoSResilienceModule
            targetUrl={domain}
            ddosData={ddosData}
            isLoading={isLoading}
            onRunTest={handleRunStressTest}
          />
        )}

        {activeTab === 'copilot' && (
          <AICopilotModule
            domain={domain}
            theme={theme}
            context={{
              whois: whoisData,
              audit: auditData,
              ports: portData,
              ddos: ddosData,
              malware: malwareData
            }}
          />
        )}

        {activeTab === 'ceh' && (
          <CEHKnowledgeBase />
        )}

        {activeTab === 'report' && (
          <ReportModule
            domain={domain}
            whoisData={whoisData}
            auditData={auditData}
            portData={portData}
            ddosData={ddosData}
            malwareData={malwareData}
            aiAnalysis={aiAnalysis}
            onGenerateAiAnalysis={handleGenerateAiReport}
            isAiGenerating={isAiGenerating}
            theme={theme}
          />
        )}

        {/* Global Live Terminal Output Console (Clean Minimalist Dark Card) */}
        <section className="bg-slate-900 rounded-xl p-4 shadow-md border border-slate-800 text-xs flex flex-col gap-2 transition-all duration-350 no-print">
          <div 
            onClick={() => setIsTerminalCollapsed(!isTerminalCollapsed)}
            className="flex justify-between items-center pb-2 mb-1 border-b border-slate-800/60 cursor-pointer select-none group"
            title="Click to expand/collapse terminal console"
          >
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 group-hover:text-emerald-400 transition-colors">
                Sentinel OS Interactive Console
              </span>
            </div>
            <div className="flex items-center gap-3 font-mono text-[10px]">
              <span className="text-slate-500">root@sentinel:~# {isTerminalCollapsed ? 'collapsed' : 'active'}</span>
              <button
                type="button"
                className="text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer p-0.5"
                aria-label="Toggle collapse state"
              >
                {isTerminalCollapsed ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronUp className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          </div>

          {!isTerminalCollapsed && (
            <>
              <div className="font-mono text-[11px] text-green-400/90 space-y-1 max-h-36 overflow-y-auto pr-1">
                {terminalLogs.map((log, index) => (
                  <div key={index} className="leading-tight">{log}</div>
                ))}
                <div className="text-white animate-pulse inline-block">_</div>
              </div>
              
              {/* Interactive Console Prompt Input */}
              <form onSubmit={handleConsoleSubmit} className="mt-2 pt-2 border-t border-slate-800/80 flex items-center gap-2 font-mono">
                <span className="text-emerald-500 font-black select-none text-[11px]">root@sentinel:~#</span>
                <input
                  type="text"
                  value={consoleCommand}
                  onChange={(e) => setConsoleCommand(e.target.value)}
                  onKeyDown={handleConsoleKeyDown}
                  placeholder="Type security commands... (try 'help', 'status', 'ping', 'nmap')"
                  className="flex-1 bg-transparent text-emerald-300 border-none outline-hidden p-0 focus:ring-0 focus:outline-hidden placeholder-slate-600 text-[11px]"
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                />
                <button
                  type="submit"
                  className="text-[10px] bg-slate-800 text-slate-400 px-2.5 py-1 rounded hover:bg-slate-750 hover:text-emerald-400 font-mono transition-colors border border-slate-700/50 cursor-pointer"
                >
                  RUN
                </button>
              </form>
            </>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 px-6 py-4 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-wrap justify-between items-center gap-4 text-[11px] text-slate-500">
          <div className="flex items-center gap-4">
            <span className="font-bold text-slate-700">SENTINEL OS PENTEST SUITE</span>
            <span>•</span>
            <span>EC-Council CEH v13 Curricula Aligned</span>
            <span>•</span>
            <span>who.is Reconnaissance Integration</span>
          </div>
          <div className="text-slate-400 font-mono">
            RFC 793 TCP Probing • DoS Benchmark Engine • Gemini 3.7 Flash
          </div>
        </div>
      </footer>
      {/* Global Real-Time Toast Notification System */}
      <Toaster
        position="top-right"
        richColors
        expand={true}
        closeButton
        theme={theme === 'cyberpunk' ? 'dark' : 'light'}
      />
    </div>
  );
}
