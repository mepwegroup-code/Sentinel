import React, { useState, useEffect } from 'react';
import { 
  X, Globe, Terminal, ExternalLink, Copy, Check, RefreshCw, Send, 
  Shield, ShieldAlert, Lock, Code2, Eye, Server, Layers, AlertCircle, 
  CheckCircle2, AlertTriangle, ArrowRight, Zap, Radio
} from 'lucide-react';
import { PortScanResult, PortHttpAccessResult, PortSocketAccessResult } from '../types';

interface PortAccessModalProps {
  port: PortScanResult;
  host: string;
  onClose: () => void;
}

export const PortAccessModal: React.FC<PortAccessModalProps> = ({ port, host, onClose }) => {
  const isWebDefault = port.isWeb ?? [80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 8008, 9000].includes(port.port);
  const initialProtocol = (port.port === 443 || port.port === 8443) ? 'https' : (isWebDefault ? 'http' : 'http');
  
  const [activeTab, setActiveTab] = useState<'web' | 'socket' | 'cli'>(isWebDefault ? 'web' : 'socket');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Web Access State
  const [webPath, setWebPath] = useState<string>('/');
  const [webMethod, setWebMethod] = useState<'GET' | 'HEAD' | 'OPTIONS' | 'POST'>('GET');
  const [webProtocol, setWebProtocol] = useState<'http' | 'https'>(initialProtocol);
  const [isWebLoading, setIsWebLoading] = useState<boolean>(false);
  const [webResult, setWebResult] = useState<PortHttpAccessResult | null>(null);
  const [webSubTab, setWebSubTab] = useState<'preview' | 'body' | 'headers' | 'security' | 'tls'>('body');

  // Socket Console State
  const [socketPayload, setSocketPayload] = useState<string>('');
  const [isSocketLoading, setIsSocketLoading] = useState<boolean>(false);
  const [socketResult, setSocketResult] = useState<PortSocketAccessResult | null>(null);
  const [socketViewMode, setSocketViewMode] = useState<'ascii' | 'hex'>('ascii');

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Perform Web Request
  const handleFetchWeb = async (overridePath?: string, overrideMethod?: 'GET' | 'HEAD' | 'OPTIONS' | 'POST') => {
    setIsWebLoading(true);
    const pathToSend = overridePath !== undefined ? overridePath : webPath;
    const methodToSend = overrideMethod || webMethod;
    if (overridePath !== undefined) setWebPath(overridePath);
    if (overrideMethod) setWebMethod(overrideMethod);

    try {
      const res = await fetch('/api/port-access/http', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host,
          port: port.port,
          protocol: webProtocol,
          path: pathToSend,
          method: methodToSend
        })
      });

      if (res.ok) {
        const data = await res.json();
        setWebResult(data);
        if (data.htmlTitle || data.contentType?.includes('html')) {
          setWebSubTab('preview');
        } else {
          setWebSubTab('body');
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsWebLoading(false);
    }
  };

  // Perform Socket Connection / Probe
  const handleConnectSocket = async (customPayload?: string) => {
    setIsSocketLoading(true);
    const payloadToSend = customPayload !== undefined ? customPayload : socketPayload;
    if (customPayload !== undefined) setSocketPayload(customPayload);

    try {
      const res = await fetch('/api/port-access/socket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host,
          port: port.port,
          payload: payloadToSend,
          useTls: port.port === 443 || port.port === 8443
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSocketResult(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsSocketLoading(false);
    }
  };

  // Initial access trigger on modal open
  useEffect(() => {
    if (isWebDefault) {
      handleFetchWeb('/');
    } else {
      handleConnectSocket('');
    }
  }, [port.port, host]);

  const externalUrl = `${webProtocol}://${host}${((webProtocol === 'http' && port.port === 80) || (webProtocol === 'https' && port.port === 443)) ? '' : `:${port.port}`}${webPath}`;

  // Protocol presets for Socket Console
  const getProtocolPresets = () => {
    switch (port.port) {
      case 21: // FTP
        return [
          { label: 'Chào mừng (Banner)', payload: '' },
          { label: 'USER anonymous', payload: 'USER anonymous\r\nPASS guest' },
          { label: 'Lệnh HELP', payload: 'HELP' },
          { label: 'Lệnh SYST', payload: 'SYST' }
        ];
      case 22: // SSH
        return [
          { label: 'Bắt tay SSH (Banner Grab)', payload: '' },
          { label: 'SSH Client ID', payload: 'SSH-2.0-OpenSSH_9.0\r\n' }
        ];
      case 23: // Telnet
        return [
          { label: 'Kết nối Telnet Banner', payload: '' },
          { label: 'IAC DO TERMINAL', payload: '\xff\xfd\x18' }
        ];
      case 25: // SMTP
      case 587:
        return [
          { label: 'Banner SMTP', payload: '' },
          { label: 'EHLO test.lan', payload: 'EHLO security-probe.lan' },
          { label: 'Lệnh HELP', payload: 'HELP' },
          { label: 'VRFY root', payload: 'VRFY root' }
        ];
      case 80: // HTTP
      case 8080:
      case 8888:
        return [
          { label: 'GET / HTTP/1.0', payload: `GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n` },
          { label: 'HEAD / HTTP/1.1', payload: `HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n` },
          { label: 'OPTIONS * HTTP/1.1', payload: `OPTIONS * HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n` }
        ];
      case 6379: // Redis
        return [
          { label: 'PING', payload: 'PING\r\n' },
          { label: 'INFO', payload: 'INFO\r\n' }
        ];
      case 3306: // MySQL
        return [
          { label: 'Đọc gói tin Handshake', payload: '' }
        ];
      default:
        return [
          { label: 'Đọc Banner mặc định', payload: '' },
          { label: 'GET / HTTP/1.0', payload: `GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n` },
          { label: 'HELP', payload: 'HELP\r\n' }
        ];
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/70 backdrop-blur-xs animate-in fade-in duration-200">
      <div 
        className="bg-white border border-slate-200 w-full max-w-4xl max-h-[92vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-800"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/80">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-white shadow-sm ${
              isWebDefault ? 'bg-blue-600' : 'bg-slate-800'
            }`}>
              {isWebDefault ? <Globe className="w-5 h-5" /> : <Terminal className="w-5 h-5" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base text-slate-900">
                  Truy Cập Cổng Mở {port.port}/tcp
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-emerald-100 text-emerald-800 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-600" /> ĐANG MỞ (OPEN)
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                  port.riskLevel === 'Critical' ? 'bg-red-100 text-red-800' :
                  port.riskLevel === 'High' ? 'bg-orange-100 text-orange-800' :
                  port.riskLevel === 'Medium' ? 'bg-amber-100 text-amber-800' :
                  'bg-blue-50 text-blue-700'
                }`}>
                  Rủi ro: {port.riskLevel || 'Low'}
                </span>
              </div>
              <div className="text-xs text-slate-500 flex items-center gap-2 mt-0.5 font-mono">
                <span>Dịch vụ: <strong>{port.service}</strong></span>
                <span>•</span>
                <span>Mục tiêu: <strong className="text-slate-800">{host}:{port.port}</strong></span>
                <button
                  onClick={() => handleCopy(`${host}:${port.port}`, 'header-target')}
                  className="p-1 rounded hover:bg-slate-200 text-slate-400 hover:text-slate-700 cursor-pointer"
                  title="Sao chép Host:Port"
                >
                  {copiedKey === 'header-target' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="p-2 rounded-xl hover:bg-slate-200/70 text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Access Modes Tab Switcher */}
        <div className="px-5 border-b border-slate-200 flex items-center gap-2 bg-white text-xs font-semibold">
          <button
            onClick={() => setActiveTab('web')}
            className={`py-3 px-3.5 border-b-2 flex items-center gap-2 cursor-pointer transition-all ${
              activeTab === 'web'
                ? 'border-blue-600 text-blue-600 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Trình Kiểm Tra Web (HTTP / HTTPS)</span>
            {isWebDefault && (
              <span className="bg-blue-100 text-blue-700 text-[9px] px-1.5 py-0.2 rounded-full font-mono font-normal">
                Khuyên dùng
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('socket')}
            className={`py-3 px-3.5 border-b-2 flex items-center gap-2 cursor-pointer transition-all ${
              activeTab === 'socket'
                ? 'border-blue-600 text-blue-600 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Terminal TCP Socket & Bắt Tay Daemon</span>
            {!isWebDefault && (
              <span className="bg-slate-100 text-slate-700 text-[9px] px-1.5 py-0.2 rounded-full font-mono font-normal">
                Mặc định TCP
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('cli')}
            className={`py-3 px-3.5 border-b-2 flex items-center gap-2 cursor-pointer transition-all ${
              activeTab === 'cli'
                ? 'border-blue-600 text-blue-600 font-bold'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Code2 className="w-4 h-4" />
            <span>Lệnh Kết Nối CLI & Shell</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
          
          {/* ========================================================= */}
          {/* TAB 1: HTTP / WEB INSPECTOR & ACCESS                      */}
          {/* ========================================================= */}
          {activeTab === 'web' && (
            <div className="space-y-4">
              {/* URL Address Bar & Controls */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
                  <select
                    value={webProtocol}
                    onChange={(e) => setWebProtocol(e.target.value as any)}
                    className="px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-mono font-bold text-slate-700 focus:outline-none focus:border-blue-500"
                  >
                    <option value="http">http://</option>
                    <option value="https">https://</option>
                  </select>

                  <select
                    value={webMethod}
                    onChange={(e) => setWebMethod(e.target.value as any)}
                    className="px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-mono font-bold text-slate-700 focus:outline-none focus:border-blue-500"
                  >
                    <option value="GET">GET</option>
                    <option value="HEAD">HEAD</option>
                    <option value="OPTIONS">OPTIONS</option>
                    <option value="POST">POST</option>
                  </select>

                  <div className="flex-1 flex items-center bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500 text-xs font-mono">
                    <span className="text-slate-400 select-none mr-1">{host}:{port.port}</span>
                    <input
                      type="text"
                      value={webPath}
                      onChange={(e) => setWebPath(e.target.value)}
                      placeholder="/ (đường dẫn tài nguyên)"
                      className="flex-1 bg-transparent focus:outline-none text-slate-800"
                      onKeyDown={(e) => e.key === 'Enter' && handleFetchWeb()}
                    />
                  </div>

                  <button
                    onClick={() => handleFetchWeb()}
                    disabled={isWebLoading}
                    className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 cursor-pointer shadow-xs transition-all"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isWebLoading ? 'animate-spin' : ''}`} />
                    <span>{isWebLoading ? 'Đang gửi...' : 'Gửi Request'}</span>
                  </button>

                  <a
                    href={externalUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 cursor-pointer shadow-2xs transition-all"
                    title="Mở cổng trong tab trình duyệt mới"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-blue-600" />
                    <span>Mở Tab Mới</span>
                  </a>
                </div>

                {/* Quick Paths */}
                <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-200/60">
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Đường Dẫn Nhanh:</span>
                  {[
                    '/',
                    '/robots.txt',
                    '/admin',
                    '/login',
                    '/api/health',
                    '/.git/config',
                    '/.env',
                    '/favicon.ico'
                  ].map((p) => (
                    <button
                      key={p}
                      onClick={() => handleFetchWeb(p)}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        webPath === p 
                          ? 'bg-blue-600 text-white font-bold' 
                          : 'bg-white hover:bg-slate-200 text-slate-700 border border-slate-200'
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>

              {/* Response Summary Bar */}
              {webResult && (
                <div className="p-3 rounded-xl bg-slate-900 text-white flex flex-wrap items-center justify-between gap-3 text-xs font-mono shadow-sm">
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-1 rounded-md font-bold text-xs ${
                      webResult.statusCode >= 200 && webResult.statusCode < 300 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                      webResult.statusCode >= 300 && webResult.statusCode < 400 ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                      webResult.statusCode >= 400 && webResult.statusCode < 500 ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      webResult.statusCode >= 500 ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {webResult.statusCode} {webResult.statusMessage || 'Response'}
                    </span>
                    <span className="text-slate-400">Thời gian: <strong className="text-emerald-400">{webResult.responseTimeMs}ms</strong></span>
                    {webResult.serverBanner && (
                      <span className="text-slate-400">Server: <strong className="text-cyan-300">{webResult.serverBanner}</strong></span>
                    )}
                    {webResult.htmlTitle && (
                      <span className="text-slate-400 max-w-xs truncate">Tiêu đề: <strong className="text-yellow-300">"{webResult.htmlTitle}"</strong></span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-400">{webResult.contentType || 'unknown/type'}</span>
                    <button
                      onClick={() => handleCopy(webResult.bodyPreview, 'web-body')}
                      className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      {copiedKey === 'web-body' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Sao chép nội dung</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Web SubTabs */}
              <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
                <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-3 text-xs font-semibold">
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setWebSubTab('preview')}
                      className={`px-3 py-2 border-b-2 cursor-pointer transition-all ${
                        webSubTab === 'preview' ? 'border-blue-600 text-blue-600 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      <Eye className="w-3.5 h-3.5 inline mr-1" />
                      Trình Xem Giao Diện (Preview)
                    </button>
                    <button
                      onClick={() => setWebSubTab('body')}
                      className={`px-3 py-2 border-b-2 cursor-pointer transition-all ${
                        webSubTab === 'body' ? 'border-blue-600 text-blue-600 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      <Code2 className="w-3.5 h-3.5 inline mr-1" />
                      Mã Nguồn Phản Hồi (Body)
                    </button>
                    <button
                      onClick={() => setWebSubTab('headers')}
                      className={`px-3 py-2 border-b-2 cursor-pointer transition-all ${
                        webSubTab === 'headers' ? 'border-blue-600 text-blue-600 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      <Layers className="w-3.5 h-3.5 inline mr-1" />
                      Headers ({webResult ? Object.keys(webResult.headers).length : 0})
                    </button>
                    <button
                      onClick={() => setWebSubTab('security')}
                      className={`px-3 py-2 border-b-2 cursor-pointer transition-all ${
                        webSubTab === 'security' ? 'border-blue-600 text-blue-600 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      <Shield className="w-3.5 h-3.5 inline mr-1" />
                      Kiểm Tra An Ninh Cổng
                    </button>
                    {webResult?.certInfo && (
                      <button
                        onClick={() => setWebSubTab('tls')}
                        className={`px-3 py-2 border-b-2 cursor-pointer transition-all ${
                          webSubTab === 'tls' ? 'border-blue-600 text-blue-600 font-bold' : 'border-transparent text-slate-500 hover:text-slate-800'
                        }`}
                      >
                        <Lock className="w-3.5 h-3.5 inline mr-1" />
                        Chứng Chỉ TLS / SSL
                      </button>
                    )}
                  </div>
                </div>

                {/* SubTab Content */}
                <div className="p-4">
                  {isWebLoading ? (
                    <div className="py-12 flex flex-col items-center justify-center text-slate-400 text-xs">
                      <RefreshCw className="w-6 h-6 animate-spin text-blue-600 mb-2" />
                      <span>Đang kết nối tới cổng {port.port}...</span>
                    </div>
                  ) : !webResult ? (
                    <div className="py-12 text-center text-slate-400 text-xs font-mono">
                      Nhấn "Gửi Request" để tải dữ liệu trực tiếp từ cổng web {port.port}
                    </div>
                  ) : (
                    <>
                      {/* SubTab: Preview */}
                      {webSubTab === 'preview' && (
                        <div className="space-y-3">
                          <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
                              <span>Trình xem phản hồi HTML qua proxy sandbox bảo mật.</span>
                            </div>
                            <a
                              href={externalUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-bold underline flex items-center gap-1 hover:text-amber-900"
                            >
                              <span>Mở trực tiếp</span>
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                          <div className="border border-slate-200 rounded-lg overflow-hidden bg-white min-h-[350px] max-h-[500px]">
                            <iframe
                              srcDoc={webResult.bodyPreview || '<h1>Không có nội dung trả về</h1>'}
                              title="Web Port Live Preview"
                              sandbox="allow-same-origin"
                              className="w-full h-[400px] border-0"
                            />
                          </div>
                        </div>
                      )}

                      {/* SubTab: Body */}
                      {webSubTab === 'body' && (
                        <div className="relative">
                          <pre className="p-4 rounded-xl bg-slate-900 text-emerald-400 font-mono text-xs overflow-x-auto max-h-[420px] leading-relaxed whitespace-pre-wrap">
                            {webResult.bodyPreview || '(Phản hồi rỗng - Empty Body)'}
                          </pre>
                        </div>
                      )}

                      {/* SubTab: Headers */}
                      {webSubTab === 'headers' && (
                        <div className="overflow-x-auto">
                          <table className="w-full text-left text-xs font-mono border-collapse">
                            <thead>
                              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px]">
                                <th className="p-2.5">Header Name</th>
                                <th className="p-2.5">Header Value</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                              {Object.entries(webResult.headers).map(([k, v]) => (
                                <tr key={k} className="hover:bg-slate-50">
                                  <td className="p-2.5 font-bold text-indigo-600 w-1/3">{k}</td>
                                  <td className="p-2.5 text-slate-800 break-all">{v}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}

                      {/* SubTab: Security Audit */}
                      {webSubTab === 'security' && (
                        <div className="space-y-4">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                            <div className={`p-3 rounded-xl border flex items-start gap-3 ${
                              webResult.securityHeadersStatus?.hsts ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-red-50 border-red-200 text-red-900'
                            }`}>
                              {webResult.securityHeadersStatus?.hsts ? <CheckCircle2 className="w-4 h-4 text-emerald-600 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5" />}
                              <div>
                                <div className="font-bold">Strict-Transport-Security (HSTS)</div>
                                <div className="text-[11px] opacity-80 mt-0.5">
                                  {webResult.securityHeadersStatus?.hsts ? 'Đã bật: Ép buộc kết nối mã hóa SSL/TLS.' : 'Chưa bật: Có nguy cơ bị tấn công SSL Strip và nghe lén.'}
                                </div>
                              </div>
                            </div>

                            <div className={`p-3 rounded-xl border flex items-start gap-3 ${
                              webResult.securityHeadersStatus?.csp ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-red-50 border-red-200 text-red-900'
                            }`}>
                              {webResult.securityHeadersStatus?.csp ? <CheckCircle2 className="w-4 h-4 text-emerald-600 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5" />}
                              <div>
                                <div className="font-bold">Content-Security-Policy (CSP)</div>
                                <div className="text-[11px] opacity-80 mt-0.5">
                                  {webResult.securityHeadersStatus?.csp ? 'Đã bật: Giới hạn nguồn script chống XSS.' : 'Chưa bật: Nguy cơ chèn mã độc Cross-Site Scripting (XSS).'}
                                </div>
                              </div>
                            </div>

                            <div className={`p-3 rounded-xl border flex items-start gap-3 ${
                              webResult.securityHeadersStatus?.xFrameOptions ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-amber-50 border-amber-200 text-amber-900'
                            }`}>
                              {webResult.securityHeadersStatus?.xFrameOptions ? <CheckCircle2 className="w-4 h-4 text-emerald-600 mt-0.5" /> : <AlertCircle className="w-4 h-4 text-amber-600 mt-0.5" />}
                              <div>
                                <div className="font-bold">X-Frame-Options (Clickjacking)</div>
                                <div className="text-[11px] opacity-80 mt-0.5">
                                  {webResult.securityHeadersStatus?.xFrameOptions ? 'Đã bật: Chặn nhúng iframe bên ngoài.' : 'Thiếu: Có thể bị tấn công Clickjacking giao diện.'}
                                </div>
                              </div>
                            </div>

                            <div className={`p-3 rounded-xl border flex items-start gap-3 ${
                              webResult.securityHeadersStatus?.xContentTypeOptions ? 'bg-emerald-50 border-emerald-200 text-emerald-900' : 'bg-amber-50 border-amber-200 text-amber-900'
                            }`}>
                              {webResult.securityHeadersStatus?.xContentTypeOptions ? <CheckCircle2 className="w-4 h-4 text-emerald-600 mt-0.5" /> : <AlertCircle className="w-4 h-4 text-amber-600 mt-0.5" />}
                              <div>
                                <div className="font-bold">X-Content-Type-Options (nosniff)</div>
                                <div className="text-[11px] opacity-80 mt-0.5">
                                  {webResult.securityHeadersStatus?.xContentTypeOptions ? 'Đã bật: Chống MIME-type sniffing.' : 'Thiếu: Trình duyệt có thể tự suy đoán sai MIME.'}
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* SubTab: TLS / SSL */}
                      {webSubTab === 'tls' && webResult.certInfo && (
                        <div className="space-y-3 font-mono text-xs">
                          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                            <div className="flex justify-between items-center py-1 border-b border-slate-200">
                              <span className="text-slate-400">Giao Thức TLS:</span>
                              <span className="font-bold text-indigo-600">{webResult.certInfo.protocol || 'TLS 1.2/1.3'}</span>
                            </div>
                            <div className="flex justify-between items-center py-1 border-b border-slate-200">
                              <span className="text-slate-400">Thuật Toán Mã Hóa (Cipher):</span>
                              <span className="font-bold text-slate-800">{webResult.certInfo.cipher || 'Standard AES-GCM'}</span>
                            </div>
                            <div className="flex justify-between items-center py-1 border-b border-slate-200">
                              <span className="text-slate-400">Tổ Chức Cấp (Issuer):</span>
                              <span className="font-bold text-slate-800">{webResult.certInfo.issuer || 'N/A'}</span>
                            </div>
                            <div className="flex justify-between items-center py-1 border-b border-slate-200">
                              <span className="text-slate-400">Tên Miền Cấp (Subject CN):</span>
                              <span className="font-bold text-slate-800">{webResult.certInfo.subject || host}</span>
                            </div>
                            <div className="flex justify-between items-center py-1">
                              <span className="text-slate-400">Hạn Chứng Chỉ (Valid To):</span>
                              <span className="font-bold text-emerald-600">{webResult.certInfo.validTo || 'N/A'}</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* TAB 2: RAW TCP SOCKET CONSOLE & BANNER GRABBER           */}
          {/* ========================================================= */}
          {activeTab === 'socket' && (
            <div className="space-y-4">
              {/* Preset Payload Buttons */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold uppercase tracking-wider text-slate-500 text-[10px]">
                    Các Lệnh Thăm Dò Nhanh Theo Giao Thức:
                  </span>
                  <span className="font-mono text-slate-400 text-[10px]">Port {port.port} ({port.service})</span>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {getProtocolPresets().map((preset, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleConnectSocket(preset.payload)}
                      className="px-2.5 py-1 bg-white hover:bg-slate-200 border border-slate-300 rounded-lg text-xs font-mono font-medium text-slate-700 transition-colors cursor-pointer shadow-2xs"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Socket Command Input Bar */}
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-emerald-400 focus-within:border-indigo-500 shadow-inner">
                  <span className="text-slate-500 select-none mr-2">$ send &gt;</span>
                  <input
                    type="text"
                    value={socketPayload}
                    onChange={(e) => setSocketPayload(e.target.value)}
                    placeholder="Nhập chuỗi ký tự hoặc lệnh gửi vào cổng TCP socket (hoặc để trống để lắng nghe Banner)..."
                    className="flex-1 bg-transparent focus:outline-none text-emerald-300 placeholder:text-slate-600"
                    onKeyDown={(e) => e.key === 'Enter' && handleConnectSocket()}
                  />
                </div>

                <button
                  onClick={() => handleConnectSocket()}
                  disabled={isSocketLoading}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold font-mono flex items-center gap-1.5 cursor-pointer shadow-xs transition-all"
                >
                  <Send className={`w-3.5 h-3.5 ${isSocketLoading ? 'animate-spin' : ''}`} />
                  <span>{isSocketLoading ? 'Đang gửi...' : 'Gửi Socket'}</span>
                </button>
              </div>

              {/* Socket Output Box */}
              <div className="rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden shadow-xl text-xs font-mono">
                {/* Terminal Header */}
                <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-slate-400 text-[11px]">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></div>
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
                    <span className="font-bold text-slate-300 ml-2">TCP SOCKET CONSOLE — {host}:{port.port}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {socketResult && (
                      <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-2 py-0.5 rounded">
                        Độ trễ: {socketResult.connectTimeMs}ms • {socketResult.bytesReceived} bytes
                      </span>
                    )}

                    <div className="flex items-center border border-slate-700 rounded-md overflow-hidden text-[10px]">
                      <button
                        onClick={() => setSocketViewMode('ascii')}
                        className={`px-2 py-0.5 cursor-pointer transition-colors ${socketViewMode === 'ascii' ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400 hover:bg-slate-800'}`}
                      >
                        ASCII
                      </button>
                      <button
                        onClick={() => setSocketViewMode('hex')}
                        className={`px-2 py-0.5 cursor-pointer transition-colors ${socketViewMode === 'hex' ? 'bg-indigo-600 text-white font-bold' : 'text-slate-400 hover:bg-slate-800'}`}
                      >
                        HEX DUMP
                      </button>
                    </div>

                    <button
                      onClick={() => handleCopy(socketViewMode === 'ascii' ? (socketResult?.rawAscii || '') : (socketResult?.hexDump || ''), 'socket-copy')}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 cursor-pointer"
                      title="Sao chép kết quả socket"
                    >
                      {copiedKey === 'socket-copy' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {/* Terminal Screen */}
                <div className="p-4 min-h-[250px] max-h-[420px] overflow-y-auto space-y-3">
                  {isSocketLoading ? (
                    <div className="py-12 flex flex-col items-center justify-center text-slate-500">
                      <RefreshCw className="w-6 h-6 animate-spin text-indigo-400 mb-2" />
                      <span>Đang mở kết nối TCP socket tới {host}:{port.port}...</span>
                    </div>
                  ) : !socketResult ? (
                    <div className="text-slate-500 py-12 text-center">
                      Nhấn "Gửi Socket" hoặc chọn một lệnh phía trên để bắt tay và trích xuất dữ liệu phản hồi.
                    </div>
                  ) : (
                    <>
                      {/* Service Identification Pill */}
                      {socketResult.serviceFingerprint && (
                        <div className="p-2.5 rounded-lg bg-indigo-950/40 border border-indigo-800/40 text-indigo-300 text-[11px] flex items-center justify-between">
                          <span>Dấu hiệu nhận diện (Service Fingerprint):</span>
                          <strong className="text-white font-bold">{socketResult.serviceFingerprint}</strong>
                        </div>
                      )}

                      {/* Display Data */}
                      {socketViewMode === 'ascii' ? (
                        <pre className="text-emerald-400 whitespace-pre-wrap leading-relaxed">
                          {socketResult.rawAscii || '(Không có byte dữ liệu nào được trả về từ máy chủ)'}
                        </pre>
                      ) : (
                        <pre className="text-cyan-300 whitespace-pre font-mono text-[11px] leading-tight">
                          {socketResult.hexDump || '(Gói tin rỗng)'}
                        </pre>
                      )}

                      {socketResult.error && (
                        <div className="text-red-400 text-[11px] mt-2 border-t border-red-900/40 pt-2 flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          <span>Thông báo socket: {socketResult.error}</span>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ========================================================= */}
          {/* TAB 3: CLI COMMANDS & CONNECTION STRINGS                  */}
          {/* ========================================================= */}
          {activeTab === 'cli' && (
            <div className="space-y-4 text-xs font-mono">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-600 text-xs font-sans">
                Các lệnh terminal tiêu chuẩn để truy cập và tương tác trực tiếp với cổng <strong>{port.port}/tcp</strong> từ máy trạm của bạn (macOS, Linux, WSL hoặc Windows Terminal):
              </div>

              <div className="space-y-3">
                {[
                  {
                    tool: 'Netcat (nc) - Thăm Dò TCP Socket Thuần',
                    cmd: `nc -v -w 3 ${host} ${port.port}`,
                    desc: 'Mở socket TCP 2 chiều để tương tác nhập xuất dòng lệnh với service'
                  },
                  {
                    tool: 'cURL - Kiểm Tra HTTP / Banner Cổng',
                    cmd: isWebDefault 
                      ? `curl -iv -k ${webProtocol}://${host}:${port.port}/` 
                      : `curl -v telnet://${host}:${port.port}`,
                    desc: 'Truy vấn thông tin tiêu đề phản hồi, status code và chi tiết kết nối'
                  },
                  {
                    tool: 'Nmap - Quét Nhận Diện Chi Tiết Phiên Bản Daemon (-sV)',
                    cmd: `nmap -sV -p ${port.port} --script=banner ${host}`,
                    desc: 'Khai thác NSE script để trích xuất chính xác tên ứng dụng và phiên bản'
                  },
                  ...(port.port === 22 ? [{
                    tool: 'SSH Client - Kết Nối Shell Bảo Mật',
                    cmd: `ssh -v -p ${port.port} user@${host}`,
                    desc: 'Khởi tạo phiên điều khiển từ xa có xác thực'
                  }] : []),
                  ...(port.port === 21 ? [{
                    tool: 'FTP Client - Truy Cập Tệp Tin',
                    cmd: `ftp -p ${host} ${port.port}`,
                    desc: 'Đăng nhập vào máy chủ tệp tin FTP'
                  }] : []),
                  ...(port.port === 23 ? [{
                    tool: 'Telnet Client - Thiết Bị Đầu Cuối',
                    cmd: `telnet ${host} ${port.port}`,
                    desc: 'Giao tiếp văn bản thô không mã hóa'
                  }] : []),
                  ...(port.port === 3306 ? [{
                    tool: 'MySQL Client - Kết Nối Cơ Sở Dữ Liệu',
                    cmd: `mysql -h ${host} -P ${port.port} -u root -p`,
                    desc: 'Kết nối máy khách cơ sở dữ liệu MySQL / MariaDB'
                  }] : []),
                  ...(port.port === 443 || port.port === 8443 ? [{
                    tool: 'OpenSSL s_client - Kiểm Tra Bắt Tay SSL / TLS',
                    cmd: `openssl s_client -connect ${host}:${port.port} -showcerts`,
                    desc: 'Kiểm tra toàn bộ chuỗi chứng chỉ x509 và cipher suite mã hóa'
                  }] : [])
                ].map((item, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-slate-900 text-slate-200 space-y-2 border border-slate-800 shadow-sm">
                    <div className="flex justify-between items-center text-slate-400 text-[11px] font-sans">
                      <span className="font-bold text-white">{item.tool}</span>
                      <span className="text-slate-500">{item.desc}</span>
                    </div>
                    <div className="flex items-center justify-between bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 text-emerald-400">
                      <code className="select-all">{item.cmd}</code>
                      <button
                        onClick={() => handleCopy(item.cmd, `cli-${idx}`)}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer ml-2"
                        title="Sao chép lệnh"
                      >
                        {copiedKey === `cli-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-100 flex items-center justify-between bg-slate-50/60 text-xs">
          <div className="text-slate-500 font-mono text-[11px]">
            {isWebDefault ? (
              <span>URL Truy cập trực tiếp: <strong className="text-slate-800">{externalUrl}</strong></span>
            ) : (
              <span>TCP Target: <strong className="text-slate-800">{host}:{port.port}</strong></span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-slate-200 hover:bg-slate-300 font-bold text-slate-700 transition-colors cursor-pointer"
            >
              Đóng
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
