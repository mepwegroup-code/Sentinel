import React, { useState, useEffect, useRef } from 'react';
import {
  Bell,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  Trash2,
  Volume2,
  VolumeX,
  X,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Zap,
  Filter
} from 'lucide-react';
import {
  SecurityAlertItem,
  getAlertHistory,
  clearAlertHistory,
  markAlertAsRead,
  markAllAlertsAsRead,
  subscribeToAlerts,
  isSoundAlertsEnabled,
  toggleSoundAlerts,
  notifyThreatDetected,
  notifyScanCompleted
} from '../utils/securityToast';

interface SecurityNotificationCenterProps {
  onSelectTab?: (tabId: string) => void;
  theme?: 'light' | 'cyberpunk';
}

export const SecurityNotificationCenter: React.FC<SecurityNotificationCenterProps> = ({
  onSelectTab,
  theme = 'light'
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlertItem[]>([]);
  const [soundEnabled, setSoundEnabled] = useState(isSoundAlertsEnabled());
  const [activeFilter, setActiveFilter] = useState<'all' | 'threats' | 'scans' | 'unread'>('all');
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsubscribe = subscribeToAlerts((newAlerts) => {
      setAlerts(newAlerts);
    });
    return () => unsubscribe();
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  const unreadCount = alerts.filter(a => !a.read).length;

  const handleToggleSound = () => {
    const next = !soundEnabled;
    setSoundEnabled(next);
    toggleSoundAlerts(next);
  };

  const handleClearAll = () => {
    clearAlertHistory();
  };

  const handleMarkAllRead = () => {
    markAllAlertsAsRead();
  };

  const handleAlertClick = (alert: SecurityAlertItem) => {
    markAlertAsRead(alert.id);
    if (alert.actionTab && onSelectTab) {
      onSelectTab(alert.actionTab);
      setIsOpen(false);
    }
  };

  // Test notification helper
  const handleTriggerTestAlert = () => {
    notifyThreatDetected({
      title: 'Phát hiện mã độc Webshell & Trojan Backdoor [CVE-2024-4577]',
      description: 'Cơ chế giám sát phát hiện kết nối C2 bất thường từ IP lạ tới cổng 443 và 8080.',
      level: 'critical',
      cveId: 'CVE-2024-4577',
      host: 'demo-target.local',
      actionTab: 'malware',
      onAction: () => {
        if (onSelectTab) onSelectTab('malware');
      }
    });
  };

  const handleTriggerScanTest = () => {
    notifyScanCompleted({
      module: 'WEB SERVER AUDIT',
      title: 'Hoàn tất đánh giá an ninh Web & SSL TLS v1.3',
      summary: 'Đã phân tích 18 tiêu chuẩn TCVN 14423 & OWASP Top 10. Điểm an ninh: 88/100.',
      target: 'example.com',
      actionTab: 'audit',
      onAction: () => {
        if (onSelectTab) onSelectTab('audit');
      }
    });
  };

  const filteredAlerts = alerts.filter(a => {
    if (activeFilter === 'unread') return !a.read;
    if (activeFilter === 'threats') return a.category === 'threat_detected' || a.severity === 'critical' || a.severity === 'high';
    if (activeFilter === 'scans') return a.category === 'scan_completed';
    return true;
  });

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Bell Notification Trigger Button */}
      <button
        id="security-notification-bell-btn"
        onClick={() => {
          setIsOpen(!isOpen);
          if (!isOpen && unreadCount > 0) {
            // mark read
          }
        }}
        className={`relative p-2 rounded-lg border transition-all cursor-pointer flex items-center justify-center ${
          unreadCount > 0
            ? 'bg-amber-500/10 border-amber-500/40 text-amber-600 hover:bg-amber-500/20'
            : 'bg-slate-100 hover:bg-slate-200 text-slate-600 border-slate-200'
        }`}
        title="Trung tâm Cảnh báo & Thông báo Real-time"
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 flex h-4 min-w-[16px] px-1 items-center justify-center rounded-full bg-rose-600 text-[10px] font-black text-white shadow-xs animate-pulse">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Flyout Notification Panel */}
      {isOpen && (
        <div
          className={`absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl shadow-2xl border z-50 overflow-hidden flex flex-col font-sans transition-all animate-fade-in ${
            theme === 'cyberpunk'
              ? 'bg-slate-950 border-cyan-500/40 text-slate-100 shadow-cyan-950/40'
              : 'bg-white border-slate-200 text-slate-900 shadow-slate-900/15'
          }`}
          style={{ maxHeight: 'calc(100vh - 120px)' }}
        >
          {/* Panel Header */}
          <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/70">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white flex items-center justify-center shadow-xs">
                <Bell className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  Cảnh Báo An Ninh Real-Time
                  {unreadCount > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500 text-white font-mono font-bold">
                      {unreadCount} mới
                    </span>
                  )}
                </h3>
                <span className="text-[10px] text-slate-500">Sentinel OS Live Threat Monitor</span>
              </div>
            </div>

            {/* Sound Toggle & Actions */}
            <div className="flex items-center gap-1.5">
              <button
                onClick={handleToggleSound}
                className={`p-1.5 rounded-lg border text-xs transition-colors cursor-pointer ${
                  soundEnabled
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                    : 'bg-slate-100 text-slate-400 border-slate-200 hover:bg-slate-200'
                }`}
                title={soundEnabled ? 'Âm thanh cảnh báo: ĐANG BẬT' : 'Âm thanh cảnh báo: ĐÃ TẮT'}
              >
                {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
              </button>

              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg hover:bg-slate-200 text-slate-400 hover:text-slate-700 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Quick Filter Tabs & Test Controls */}
          <div className="px-4 py-2 border-b border-slate-100 bg-slate-50/40 flex flex-wrap items-center justify-between gap-1.5">
            <div className="flex items-center gap-1 text-[11px]">
              <button
                onClick={() => setActiveFilter('all')}
                className={`px-2 py-0.5 rounded-md font-semibold cursor-pointer transition-all ${
                  activeFilter === 'all'
                    ? 'bg-indigo-600 text-white shadow-2xs'
                    : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                Tất cả ({alerts.length})
              </button>
              <button
                onClick={() => setActiveFilter('threats')}
                className={`px-2 py-0.5 rounded-md font-semibold cursor-pointer transition-all ${
                  activeFilter === 'threats'
                    ? 'bg-rose-600 text-white shadow-2xs'
                    : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                Nguy cấp
              </button>
              <button
                onClick={() => setActiveFilter('scans')}
                className={`px-2 py-0.5 rounded-md font-semibold cursor-pointer transition-all ${
                  activeFilter === 'scans'
                    ? 'bg-blue-600 text-white shadow-2xs'
                    : 'text-slate-600 hover:bg-slate-200'
                }`}
              >
                Quét xong
              </button>
            </div>

            {alerts.length > 0 && (
              <div className="flex items-center gap-2 text-[10px]">
                <button
                  onClick={handleMarkAllRead}
                  className="text-indigo-600 hover:underline font-semibold cursor-pointer"
                >
                  Đọc hết
                </button>
                <span className="text-slate-300">|</span>
                <button
                  onClick={handleClearAll}
                  className="text-rose-600 hover:underline font-semibold cursor-pointer flex items-center gap-0.5"
                >
                  <Trash2 className="w-3 h-3" />
                  Xóa
                </button>
              </div>
            )}
          </div>

          {/* Alert Stream List */}
          <div className="overflow-y-auto max-h-[380px] p-2 space-y-2 divide-y divide-slate-100">
            {filteredAlerts.length === 0 ? (
              <div className="p-8 text-center space-y-3">
                <div className="w-12 h-12 mx-auto rounded-full bg-slate-100 flex items-center justify-center text-slate-400">
                  <ShieldCheck className="w-6 h-6 text-emerald-500" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-800">Không có cảnh báo nào</h4>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Hệ thống an ninh đang giám sát liên tục ở chế độ thời gian thực.
                  </p>
                </div>

                {/* Quick Simulation Buttons */}
                <div className="pt-2 flex flex-col gap-1.5">
                  <button
                    onClick={handleTriggerTestAlert}
                    className="w-full px-3 py-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Thử nghiệm Toast Cảnh Báo Nguy Cấp</span>
                  </button>
                  <button
                    onClick={handleTriggerScanTest}
                    className="w-full px-3 py-1.5 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Thử nghiệm Toast Quét Hoàn Tất</span>
                  </button>
                </div>
              </div>
            ) : (
              filteredAlerts.map((item) => (
                <div
                  key={item.id}
                  onClick={() => handleAlertClick(item)}
                  className={`pt-2 p-2.5 rounded-xl transition-all cursor-pointer text-left space-y-1 ${
                    !item.read
                      ? 'bg-indigo-50/40 border border-indigo-100/80 hover:bg-indigo-50'
                      : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          item.severity === 'critical'
                            ? 'bg-rose-500 animate-ping'
                            : item.severity === 'high'
                            ? 'bg-amber-500'
                            : item.severity === 'success'
                            ? 'bg-emerald-500'
                            : 'bg-indigo-500'
                        }`}
                      />
                      <span className="text-[10px] font-bold font-mono uppercase text-slate-500">
                        {item.module || item.severity}
                      </span>
                      {item.cveId && (
                        <span className="text-[9px] font-mono font-bold bg-rose-100 text-rose-700 px-1 rounded">
                          {item.cveId}
                        </span>
                      )}
                    </div>
                    <span className="text-[9px] text-slate-400 font-mono">
                      {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </div>

                  <h5 className="text-xs font-bold text-slate-900 leading-snug">
                    {item.title}
                  </h5>

                  <p className="text-[11px] text-slate-600 line-clamp-2 leading-relaxed">
                    {item.description}
                  </p>

                  {item.actionTab && (
                    <div className="pt-1 flex items-center justify-between text-[10px] font-semibold text-indigo-600">
                      <span>Nhấp để mở module {item.actionTab.toUpperCase()}</span>
                      <ChevronRight className="w-3 h-3" />
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Footer Demo Triggers */}
          {filteredAlerts.length > 0 && (
            <div className="p-2.5 border-t border-slate-100 bg-slate-50 flex items-center justify-between gap-2 text-[10px]">
              <span className="text-slate-500 font-medium">Bảo vệ thời gian thực:</span>
              <div className="flex items-center gap-1">
                <button
                  onClick={handleTriggerTestAlert}
                  className="px-2 py-0.5 rounded bg-rose-100 hover:bg-rose-200 text-rose-800 font-bold cursor-pointer"
                >
                  + Test Cảnh Báo
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
