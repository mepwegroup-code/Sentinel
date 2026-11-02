import React, { useState } from 'react';
import { Terminal, Download, RefreshCw, Upload, Check, Copy, ShieldAlert, Cpu, AlertCircle, Info } from 'lucide-react';
import { ProvenanceBadge } from './ProvenanceBadge';

interface AgentInstructionBannerProps {
  onRefresh: () => void;
  onUploadReport?: (reportData: any) => void;
  isRefreshing?: boolean;
  serverUrl?: string;
  theme?: 'light' | 'cyberpunk';
}

export const AgentInstructionBanner: React.FC<AgentInstructionBannerProps> = ({
  onRefresh,
  onUploadReport,
  isRefreshing = false,
  serverUrl = window.location.origin,
  theme = 'light'
}) => {
  const [copied, setCopied] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const curlCmd = `curl -sSL ${serverUrl}/agent/sentinel-agent.mjs -o sentinel-agent.mjs && node sentinel-agent.mjs --server ${serverUrl}`;

  const copyCommand = () => {
    navigator.clipboard.writeText(curlCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target?.result as string);
        if (onUploadReport) {
          onUploadReport(parsed);
        }
      } catch (err: any) {
        setUploadError('Tệp JSON không hợp lệ: ' + err.message);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="bg-amber-500/5 border border-amber-500/30 rounded-2xl p-6 my-4 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-amber-500/20 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-600 border border-amber-500/20">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-slate-800 dark:text-slate-100">
                Yêu cầu Sentinel Agent cục bộ (Local LAN Discovery)
              </h3>
              <ProvenanceBadge type="unavailable" label="Không thể quét từ Cloud" />
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Để tuân thủ tuyệt đối nguyên tắc <strong>không bịa số liệu</strong>, máy chủ Cloud Run không thể quét dải IP nội bộ RFC1918 (192.168.x.x / 10.x.x.x) nếu không có Sentinel Agent.
            </p>
          </div>
        </div>

        <a
          href="/agent/sentinel-agent.mjs"
          download="sentinel-agent.mjs"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors shrink-0"
        >
          <Download className="w-4 h-4" />
          <span>Tải sentinel-agent.mjs</span>
        </a>
      </div>

      <div className="mt-5 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-3">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">
            Cách 1: Chạy trực tiếp từ Terminal trên máy tính cùng mạng Wi-Fi/LAN
          </span>
          <div className="relative group">
            <div className="bg-slate-950 rounded-xl p-3.5 font-mono text-xs text-emerald-400 overflow-x-auto border border-slate-800">
              <div className="flex items-center gap-2 text-slate-500 mb-2 border-b border-slate-800 pb-1.5 select-none">
                <Terminal className="w-3.5 h-3.5 text-amber-400" />
                <span>Bash / zsh / PowerShell (Yêu cầu Node.js 18+)</span>
              </div>
              <code>{curlCmd}</code>
            </div>
            <button
              onClick={copyCommand}
              className="absolute top-9 right-3 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-white text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Đã sao chép' : 'Sao chép lệnh'}</span>
            </button>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-colors cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{isRefreshing ? 'Đang kiểm tra kết nối...' : 'Kiểm tra kết nối Agent'}</span>
            </button>
            <span className="text-xs text-slate-500">
              Sau khi script agent hoàn tất gửi báo cáo, bấm nút này để cập nhật dữ liệu thật.
            </span>
          </div>
        </div>

        <div className="border-t lg:border-t-0 lg:border-l border-amber-500/20 lg:pl-6 space-y-3 flex flex-col justify-between">
          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block mb-2">
              Cách 2: Tải lên sentinel-lan-report.json
            </span>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Nếu máy không có kết nối ra internet, hãy chạy lệnh không có cờ <code className="bg-slate-100 dark:bg-slate-800 px-1 py-0.5 rounded text-amber-700">--server</code>, script sẽ xuất tệp JSON kết quả để bạn tải lên tại đây.
            </p>
          </div>

          <div className="pt-2">
            <label className="flex flex-col items-center justify-center p-3 border-2 border-dashed border-amber-500/40 rounded-xl cursor-pointer hover:bg-amber-500/10 transition-colors">
              <Upload className="w-5 h-5 text-amber-600 mb-1" />
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">Chọn tệp JSON báo cáo</span>
              <span className="text-[10px] text-slate-400">sentinel-lan-report.json</span>
              <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
            </label>
            {uploadError && <p className="text-xs text-rose-500 mt-1">{uploadError}</p>}
          </div>
        </div>
      </div>
    </div>
  );
};
