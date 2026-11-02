import React from 'react';
import { toast } from 'sonner';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  Terminal,
  Zap,
  Globe,
  Wifi,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Flame,
  Volume2,
  VolumeX,
  X
} from 'lucide-react';

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success';

export interface SecurityAlertItem {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  category?: 'scan_completed' | 'threat_detected' | 'system' | 'benchmark' | 'remediation';
  module?: string;
  target?: string;
  cveId?: string;
  timestamp: string;
  read?: boolean;
  actionTab?: string;
}

// Global alert listeners for real-time reactive Notification Center
type AlertListener = (alerts: SecurityAlertItem[]) => void;
const alertListeners: Set<AlertListener> = new Set();

const STORAGE_KEY = 'sentinel_security_alerts_v1';
const SOUND_KEY = 'sentinel_alert_sound_enabled';

// In-memory alert buffer
let inMemoryAlerts: SecurityAlertItem[] = [];

// Initialize history from localStorage
try {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    inMemoryAlerts = JSON.parse(saved);
  }
} catch {
  inMemoryAlerts = [];
}

const saveAlerts = () => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(inMemoryAlerts.slice(0, 100)));
  } catch {}
  alertListeners.forEach(listener => listener([...inMemoryAlerts]));
};

export const getAlertHistory = (): SecurityAlertItem[] => {
  return [...inMemoryAlerts];
};

export const clearAlertHistory = () => {
  inMemoryAlerts = [];
  saveAlerts();
};

export const markAlertAsRead = (id: string) => {
  inMemoryAlerts = inMemoryAlerts.map(a => a.id === id ? { ...a, read: true } : a);
  saveAlerts();
};

export const markAllAlertsAsRead = () => {
  inMemoryAlerts = inMemoryAlerts.map(a => ({ ...a, read: true }));
  saveAlerts();
};

export const subscribeToAlerts = (listener: AlertListener) => {
  alertListeners.add(listener);
  listener([...inMemoryAlerts]);
  return () => {
    alertListeners.delete(listener);
  };
};

export const isSoundAlertsEnabled = (): boolean => {
  try {
    const val = localStorage.getItem(SOUND_KEY);
    return val !== 'false'; // Enabled by default
  } catch {
    return true;
  }
};

export const toggleSoundAlerts = (enabled: boolean) => {
  try {
    localStorage.setItem(SOUND_KEY, String(enabled));
  } catch {}
};

// Web Audio API Sound Synthesizer for Zero-Dependency, Instant Chimes
export const playSecurityChime = (type: 'critical' | 'threat' | 'success' | 'scan_done' | 'info') => {
  if (!isSoundAlertsEnabled()) return;
  try {
    const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();

    if (type === 'critical') {
      // 2-tone urgent alarm (880Hz -> 440Hz -> 880Hz)
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.3);

      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.45);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.45);
    } else if (type === 'threat') {
      // Warning ping
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
      osc.frequency.exponentialRampToValueAtTime(369.99, ctx.currentTime + 0.25); // F#4

      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);

      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } else if (type === 'success' || type === 'scan_done') {
      // Crisp harmonic dual-beep
      const now = ctx.currentTime;
      [523.25, 659.25, 783.99].forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.08, now + i * 0.08);
        gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.08 + 0.2);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + i * 0.08);
        osc.stop(now + i * 0.08 + 0.2);
      });
    } else {
      // Subtle info blip
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      gain.gain.setValueAtTime(0.06, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.15);
    }
  } catch {}
};

const pushAlertItem = (alert: Omit<SecurityAlertItem, 'id' | 'timestamp' | 'read'>): SecurityAlertItem => {
  const newItem: SecurityAlertItem = {
    ...alert,
    id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    read: false
  };

  inMemoryAlerts = [newItem, ...inMemoryAlerts].slice(0, 100);
  saveAlerts();
  return newItem;
};

// -------------------------------------------------------------
// TOAST API TRIGGERS
// -------------------------------------------------------------

/**
 * Triggered when a new Threat / Vulnerability is discovered
 */
export const notifyThreatDetected = ({
  title,
  description,
  level = 'high',
  cveId,
  host,
  actionTab,
  onAction
}: {
  title: string;
  description: string;
  level?: 'critical' | 'high' | 'medium' | 'low';
  cveId?: string;
  host?: string;
  actionTab?: string;
  onAction?: () => void;
}) => {
  pushAlertItem({
    title,
    description,
    severity: level,
    category: 'threat_detected',
    target: host,
    cveId,
    actionTab
  });

  playSecurityChime(level === 'critical' ? 'critical' : 'threat');

  const isCritical = level === 'critical';
  const isHigh = level === 'high';

  toast.custom((t) => (
    <div
      className={`relative w-full max-w-md p-4 rounded-xl border shadow-2xl backdrop-blur-md transition-all duration-300 font-sans ${
        isCritical
          ? 'bg-rose-950/95 text-rose-50 border-rose-500/70 shadow-rose-900/50'
          : isHigh
          ? 'bg-amber-950/95 text-amber-50 border-amber-500/60 shadow-amber-900/40'
          : 'bg-slate-900/95 text-slate-100 border-slate-700 shadow-slate-950/50'
      }`}
    >
      <div className="flex items-start gap-3">
        <div
          className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
            isCritical
              ? 'bg-rose-600/30 border-rose-400 text-rose-300 animate-pulse'
              : isHigh
              ? 'bg-amber-600/30 border-amber-400 text-amber-300'
              : 'bg-indigo-600/30 border-indigo-400 text-indigo-300'
          }`}
        >
          {isCritical ? <ShieldAlert className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <span
                className={`text-[10px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded ${
                  isCritical
                    ? 'bg-rose-500 text-white shadow-xs'
                    : isHigh
                    ? 'bg-amber-500 text-slate-950 font-bold'
                    : 'bg-indigo-500 text-white'
                }`}
              >
                {level.toUpperCase()} THREAT
              </span>
              {cveId && (
                <span className="text-[10px] font-mono text-rose-300 border border-rose-400/40 px-1 py-0.2 rounded">
                  {cveId}
                </span>
              )}
            </div>
            <button
              onClick={() => toast.dismiss(t)}
              className="text-slate-400 hover:text-white cursor-pointer p-0.5 rounded transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <h4 className="text-xs font-bold mt-1 text-white tracking-tight leading-snug">
            {title}
          </h4>

          <p className="text-[11px] text-slate-300 mt-1 line-clamp-2 leading-relaxed font-normal">
            {description}
          </p>

          {(onAction || actionTab) && (
            <div className="mt-2.5 flex items-center justify-between pt-2 border-t border-white/10">
              {host && <span className="text-[10px] font-mono text-slate-400">Host: {host}</span>}
              <button
                onClick={() => {
                  toast.dismiss(t);
                  if (onAction) onAction();
                }}
                className={`ml-auto px-2.5 py-1 rounded text-[11px] font-bold flex items-center gap-1 transition-all cursor-pointer ${
                  isCritical
                    ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-xs'
                    : 'bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold shadow-xs'
                }`}
              >
                <span>Xử Lý Lỗ Hổng</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  ), {
    duration: isCritical ? 8000 : 5500,
    position: 'top-right'
  });
};

/**
 * Triggered when a Security Scan / Assessment Module finishes
 */
export const notifyScanCompleted = ({
  module,
  title,
  summary,
  target,
  hasThreats = false,
  actionTab,
  onAction
}: {
  module: string;
  title: string;
  summary: string;
  target?: string;
  hasThreats?: boolean;
  actionTab?: string;
  onAction?: () => void;
}) => {
  pushAlertItem({
    title,
    description: summary,
    severity: hasThreats ? 'high' : 'success',
    category: 'scan_completed',
    module,
    target,
    actionTab
  });

  playSecurityChime(hasThreats ? 'threat' : 'scan_done');

  toast.custom((t) => (
    <div className="w-full max-w-md p-3.5 rounded-xl border border-slate-700 bg-slate-900/95 text-slate-100 shadow-2xl backdrop-blur-md font-sans">
      <div className="flex items-start gap-3">
        <div
          className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${
            hasThreats
              ? 'bg-amber-500/20 border-amber-500/40 text-amber-400'
              : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
          }`}
        >
          {hasThreats ? <AlertTriangle className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 uppercase">
                {module}
              </span>
              <span className="text-[10px] text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Hoàn Tất
              </span>
            </div>
            <button
              onClick={() => toast.dismiss(t)}
              className="text-slate-400 hover:text-white cursor-pointer p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <h4 className="text-xs font-bold text-white mt-1 leading-snug">
            {title}
          </h4>

          <p className="text-[11px] text-slate-300 mt-0.5 line-clamp-2 leading-relaxed">
            {summary}
          </p>

          {(onAction || actionTab) && (
            <div className="mt-2 flex items-center justify-between pt-1.5 border-t border-slate-800">
              {target && <span className="text-[10px] font-mono text-slate-400 truncate max-w-[160px]">{target}</span>}
              <button
                onClick={() => {
                  toast.dismiss(t);
                  if (onAction) onAction();
                }}
                className="ml-auto px-2 py-0.5 rounded text-[11px] font-semibold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1 cursor-pointer transition-colors"
              >
                <span>Xem Báo Cáo</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  ), {
    duration: 5000,
    position: 'top-right'
  });
};

/**
 * Standard Success Alert
 */
export const notifySecuritySuccess = (title: string, description?: string) => {
  pushAlertItem({
    title,
    description: description || 'Thao tác bảo mật hoàn tất thành công.',
    severity: 'success',
    category: 'system'
  });

  playSecurityChime('success');

  toast.success(title, {
    description,
    duration: 4000,
    position: 'top-right'
  });
};

/**
 * Standard Warning Alert
 */
export const notifySecurityWarning = (title: string, description?: string) => {
  pushAlertItem({
    title,
    description: description || 'Cảnh báo hệ thống mạng.',
    severity: 'medium',
    category: 'system'
  });

  playSecurityChime('info');

  toast.warning(title, {
    description,
    duration: 4500,
    position: 'top-right'
  });
};

/**
 * Standard Info Alert
 */
export const notifySecurityInfo = (title: string, description?: string) => {
  pushAlertItem({
    title,
    description: description || 'Thông tin trạng thái hệ thống.',
    severity: 'info',
    category: 'system'
  });

  playSecurityChime('info');

  toast.info(title, {
    description,
    duration: 4000,
    position: 'top-right'
  });
};
