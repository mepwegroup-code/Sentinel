import React from 'react';
import { Shield, Search, Terminal, RefreshCw, Cpu, Activity, FileText, BookOpen, AlertTriangle, EyeOff, Server, Database, ShieldCheck, Zap, Wifi, Globe, Network } from 'lucide-react';
import { SecurityNotificationCenter } from './SecurityNotificationCenter';

interface NavbarProps {
  domain: string;
  setDomain: (val: string) => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRunFullAudit: () => void;
  isLoading: boolean;
  theme?: 'light' | 'cyberpunk';
  setTheme?: (val: 'light' | 'cyberpunk') => void;
  onSaveSession: () => void;
  onClearSession: () => void;
  hasSavedSession: boolean;
  onAdminLoginClick: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  domain,
  setDomain,
  activeTab,
  setActiveTab,
  onRunFullAudit,
  isLoading,
  theme = 'light',
  setTheme,
  onSaveSession,
  onClearSession,
  hasSavedSession,
  onAdminLoginClick
}) => {
  const tabs = [
    { id: 'network-review', label: 'Đánh Giá Mạng & Quản Lý Endpoint', icon: Network },
    { id: 'speedtest', label: 'Đo Tốc Độ Mạng (Fast)', icon: Zap },
    { id: 'lan-intruder', label: 'Dò Kẻ Xâm Nhập LAN', icon: Wifi },
    { id: 'threat-map', label: 'Bản Đồ Nhiệt Mạng Của Bạn', icon: Globe },
    { id: 'whois', label: 'Whois & DNS Recon', icon: Search },
    { id: 'ports', label: 'Port & Service Scan', icon: Terminal },
    { id: 'audit', label: 'Web Server Audit', icon: Shield },
    { id: 'malware', label: 'Malware & Link Inspector', icon: AlertTriangle },
    { id: 'sandbox', label: 'Misconfig & Exploit Sandbox', icon: Server },
    { id: 'evasion', label: 'IDS/Firewall Evasion Lab', icon: EyeOff },
    { id: 'ddos', label: 'DDoS & Stress Benchmark', icon: Activity },
    { id: 'copilot', label: 'AI Pentest Copilot', icon: Cpu },
    { id: 'ceh', label: 'CEH v13 Knowledge', icon: BookOpen },
    { id: 'report', label: 'Audit Report', icon: FileText },
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-50 shadow-xs">
      {/* Top Banner */}
      <div className="px-6 py-3.5 flex flex-wrap items-center justify-between gap-4 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center shadow-xs">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-tight text-slate-800 uppercase">
                Sentinel OS <span className="text-blue-600 font-mono text-xs font-semibold px-1.5 py-0.5 bg-blue-50 border border-blue-200 rounded">v2.4 CEH</span>
              </h1>
            </div>
            <p className="text-[11px] text-slate-500 hidden sm:block">Professional Web Security Reconnaissance, DoS Resilience & Pentest Suite</p>
          </div>
        </div>

        {/* Target Input Bar */}
        <div className="flex items-center flex-1 max-w-xl bg-slate-50 rounded-lg px-3 py-1.5 border border-slate-200 focus-within:border-blue-500 focus-within:bg-white transition-all">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mr-2 shrink-0">TARGET:</span>
          <input
            id="target-domain-input"
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') onRunFullAudit(); }}
            placeholder="e.g. scanme.nmap.org, example.com, 93.184.216.34"
            className="bg-transparent border-none outline-hidden text-sm w-full font-mono text-slate-800 placeholder-slate-400"
          />
          <button
            id="run-full-audit-btn"
            onClick={onRunFullAudit}
            disabled={isLoading || !domain}
            className="ml-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5" />
                <span>Run Audit</span>
              </>
            )}
          </button>
        </div>

        {/* Status indicator, Notifications & Theme Toggle */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Real-time Security Notification Center */}
          <SecurityNotificationCenter onSelectTab={setActiveTab} theme={theme} />

          <button
            onClick={onAdminLoginClick}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold select-none cursor-pointer transition-all duration-300 bg-rose-50 hover:bg-rose-100 text-rose-800 border-rose-200"
            title="Admin Access"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-rose-600" />
            <span className="hidden sm:inline">Admin</span>
          </button>
          
          <button
            id="save-session-btn"
            onClick={onSaveSession}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold select-none cursor-pointer transition-all duration-300 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border-emerald-200"
            title="Persist current scan results and terminal logs to local storage"
          >
            <Database className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
            <span className="hidden sm:inline">Save Session</span>
            <span className="sm:hidden">Save</span>
          </button>

          {hasSavedSession && (
            <button
              id="clear-session-btn"
              onClick={onClearSession}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-semibold select-none cursor-pointer transition-all duration-300 bg-rose-50 hover:bg-rose-100 text-rose-800 border-rose-200 animate-fade-in"
              title="Clear saved session data"
            >
              <span>Clear</span>
            </button>
          )}

          <button
            id="theme-toggle-btn"
            onClick={() => setTheme && setTheme(theme === 'light' ? 'cyberpunk' : 'light')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold select-none cursor-pointer transition-all duration-300 bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-200"
            title="Toggle theme between Clean Minimalism and Cyberpunk Security"
          >
            {theme === 'light' ? (
              <>
                <Cpu className="w-3.5 h-3.5 text-slate-500" />
                <span className="hidden sm:inline">Cyberpunk Security</span>
                <span className="sm:hidden">Dark</span>
              </>
            ) : (
              <>
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline" style={{ color: 'var(--color-cyan-400)' }}>Clean Minimalism</span>
                <span className="sm:hidden" style={{ color: 'var(--color-cyan-400)' }}>Light</span>
              </>
            )}
          </button>

          <div className="hidden lg:flex flex-col items-end">
            <span className="text-[9px] uppercase font-bold text-slate-400">Environment</span>
            <span className="text-xs font-semibold text-emerald-600 flex items-center gap-1">
              <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
              READY & COMPLIANT
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="px-6 flex gap-1 overflow-x-auto bg-slate-50/70 border-t border-slate-100">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-btn-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-blue-600 text-blue-600 bg-white font-semibold shadow-2xs'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100/80'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-blue-600' : 'text-slate-400'}`} />
              {tab.label}
            </button>
          );
        })}
      </nav>
    </header>
  );
};
