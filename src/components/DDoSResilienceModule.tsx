import React, { useState } from 'react';
import { StressTestResult } from '../types';
import { Activity, Flame, Shield, AlertTriangle, Play, RefreshCw, BarChart2, CheckCircle2, XCircle, Info, Zap, Lock, Cpu, Server } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

interface DDoSResilienceModuleProps {
  targetUrl: string;
  ddosData: StressTestResult | null;
  isLoading: boolean;
  onRunTest: (concurrency: number, duration: number) => void;
}

export const DDoSResilienceModule: React.FC<DDoSResilienceModuleProps> = ({
  targetUrl,
  ddosData,
  isLoading,
  onRunTest
}) => {
  const [concurrency, setConcurrency] = useState(6);
  const [duration, setDuration] = useState(5);
  const [activeTab, setActiveTab] = useState<'benchmark' | 'ceh-vectors' | 'defense-rules'>('benchmark');
  const [selectedAttackVector, setSelectedAttackVector] = useState<'http2' | 'syn' | 'dns-amp' | 'slowloris'>('http2');

  const attackVectors = [
    {
      id: 'http2',
      title: 'HTTP/2 Continuation Flood',
      cve: 'CVE-2024-27983 / CEH Slide 42-43',
      type: 'Application / Protocol Layer 7',
      impact: 'Server CPU & Memory Exhaustion (Apache/Nginx/Node.js crash)',
      description: 'The attacker sends continuous HTTP/2 CONTINUATION frames over a single TCP stream without setting the END_HEADERS flag. The server allocates memory indefinitely waiting for header termination until memory is completely exhausted.',
      mitigation: 'Update web server to latest security release (Apache 2.4.59+, Nginx 1.25.5+), enforce strict http2_max_requests and max header list constraints.'
    },
    {
      id: 'syn',
      title: 'TCP SYN Flood Attack',
      cve: 'CEH Module 03 (Slide 18, 48) & Module 10',
      type: 'Transport Layer 4',
      impact: 'TCP Connection Queue / Backlog Exhaustion',
      description: 'Attacker transmits a massive flood of TCP SYN packets with spoofed source IP addresses. The target sends SYN-ACK and allocates memory in its half-open connection table, waiting for an ACK that never arrives.',
      mitigation: 'Enable TCP SYN Cookies (`sysctl -w net.ipv4.tcp_syncookies=1`), reduce SYN-ACK retries, and configure stateful firewall SYN proxying.'
    },
    {
      id: 'dns-amp',
      title: 'DNS Amplification & Reflection',
      cve: 'CEH Module 13 (Slide 28-29)',
      type: 'Network / Application Layer 7',
      impact: 'Bandwidth Saturation (50x - 100x Amplification Factor)',
      description: 'Attacker sends small recursive DNS queries (e.g. EDNS0 ANY query for large domain records) with the victim’s spoofed IP to thousands of open DNS resolvers. The resolvers reflect massive 4KB+ replies back to the victim.',
      mitigation: 'Disable open recursive resolution on authoritative DNS servers, deploy Response Rate Limiting (RRL), and enforce BCP 38 ingress filtering.'
    },
    {
      id: 'slowloris',
      title: 'Slowloris & Slow HTTP POST',
      cve: 'CEH Module 10 (Denial-of-Service)',
      type: 'Application Layer 7',
      impact: 'Thread / Worker Pool Starvation with Minimal Bandwidth',
      description: 'Attacker opens multiple connections to the target web server and sends partial HTTP headers very slowly (e.g. "X-a: b\\r\\n" every 15 seconds) to keep sockets occupied without completing the request.',
      mitigation: 'Set strict request header timeouts (e.g. `client_header_timeout 10s` in Nginx), limit concurrent connections per client IP, and deploy reverse proxy buffers.'
    }
  ];

  const currentVector = attackVectors.find(v => v.id === selectedAttackVector) || attackVectors[0];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-red-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
              DoS / DDoS Resilience & Stress Benchmark Lab
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Evaluating connection handling, rate-limiting thresholds & WAF defenses for <span className="font-mono font-bold text-slate-800">{targetUrl || 'Target'}</span>
          </p>
        </div>

        {/* View Mode Switcher */}
        <div className="flex gap-1.5 bg-slate-100 p-1 rounded-lg">
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all cursor-pointer ${
              activeTab === 'benchmark' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Live Stress Test
          </button>
          <button
            onClick={() => setActiveTab('ceh-vectors')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all cursor-pointer ${
              activeTab === 'ceh-vectors' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            CEH Attack Vectors
          </button>
          <button
            onClick={() => setActiveTab('defense-rules')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all cursor-pointer ${
              activeTab === 'defense-rules' ? 'bg-white text-blue-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Defense Rule Generator
          </button>
        </div>
      </div>

      {activeTab === 'benchmark' && (
        <>
          {/* Controls Bar */}
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
              {/* Concurrency Slider */}
              <div className="md:col-span-4">
                <div className="flex justify-between text-xs font-bold text-slate-700 mb-1">
                  <span>Concurrency (Workers):</span>
                  <span className="text-blue-600 font-mono">{concurrency} Threads</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="15"
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <span className="text-[10px] text-slate-400">Simulates simultaneous HTTP connection bursts</span>
              </div>

              {/* Duration Slider */}
              <div className="md:col-span-4">
                <div className="flex justify-between text-xs font-bold text-slate-700 mb-1">
                  <span>Test Duration:</span>
                  <span className="text-blue-600 font-mono">{duration} Seconds</span>
                </div>
                <input
                  type="range"
                  min="2"
                  max="12"
                  value={duration}
                  onChange={(e) => setDuration(Number(e.target.value))}
                  className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <span className="text-[10px] text-slate-400">Controlled execution window</span>
              </div>

              {/* Launch Button */}
              <div className="md:col-span-4 flex justify-end">
                <button
                  id="launch-stress-test-btn"
                  onClick={() => onRunTest(concurrency, duration)}
                  disabled={isLoading || !targetUrl}
                  className="w-full md:w-auto bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider px-6 py-3 rounded-lg flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Benchmarking...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4" />
                      <span>Start Stress Benchmark</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Results Display */}
          {ddosData ? (
            <div className="space-y-6">
              {/* Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                    Throughput (RPS)
                  </span>
                  <div className="text-2xl font-bold font-mono text-blue-600">
                    {ddosData.requestsPerSecond} <span className="text-xs font-sans text-slate-500 font-normal">req/s</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Total: {ddosData.totalRequests} requests</div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                    Median Latency (p50)
                  </span>
                  <div className="text-2xl font-bold font-mono text-slate-800">
                    {ddosData.p50LatencyMs} <span className="text-xs font-sans text-slate-500 font-normal">ms</span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Avg: {ddosData.avgLatencyMs}ms | p99: {ddosData.p99LatencyMs}ms</div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                    DDoS / WAF Shield
                  </span>
                  <div className="text-sm font-bold text-slate-800 truncate" title={ddosData.wafProvider}>
                    {ddosData.wafDetected ? 'Active WAF Shield' : 'Origin Server'}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 truncate">{ddosData.wafProvider}</div>
                </div>

                <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                    Resilience Status
                  </span>
                  <div className="text-sm font-bold flex items-center gap-1.5">
                    {ddosData.resilienceRating === 'Resilient' ? (
                      <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded text-xs">High Resilience</span>
                    ) : ddosData.resilienceRating === 'Rate-Limited' ? (
                      <span className="text-blue-700 bg-blue-50 px-2 py-0.5 rounded text-xs">Rate Limiting Active (429)</span>
                    ) : (
                      <span className="text-red-700 bg-red-50 px-2 py-0.5 rounded text-xs">Elevated Latency Spike</span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">Success: {ddosData.successfulRequests} / {ddosData.totalRequests}</div>
                </div>
              </div>

              {/* Real-Time Latency & Throughput Graph */}
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs">
                <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-600 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-blue-600" />
                    Throughput (RPS) & Response Latency Response Curve
                  </h3>
                  <span className="text-[11px] font-mono text-slate-400">Time Window: {ddosData.durationSeconds}s</span>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={ddosData.timeSeries.length > 0 ? ddosData.timeSeries : [
                      { timeOffset: 1, rps: ddosData.requestsPerSecond * 0.8, latency: ddosData.avgLatencyMs * 0.9 },
                      { timeOffset: 2, rps: ddosData.requestsPerSecond, latency: ddosData.avgLatencyMs },
                      { timeOffset: 3, rps: ddosData.requestsPerSecond * 1.1, latency: ddosData.avgLatencyMs * 1.05 },
                      { timeOffset: 4, rps: ddosData.requestsPerSecond * 0.95, latency: ddosData.avgLatencyMs * 0.98 },
                      { timeOffset: 5, rps: ddosData.requestsPerSecond, latency: ddosData.avgLatencyMs },
                    ]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                      <XAxis dataKey="timeOffset" tick={{ fontSize: 11 }} label={{ value: 'Seconds Elapsed', position: 'insideBottomRight', offset: -5 }} />
                      <YAxis yAxisId="left" tick={{ fontSize: 11 }} label={{ value: 'Latency (ms)', angle: -90, position: 'insideLeft' }} />
                      <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 11 }} label={{ value: 'RPS', angle: 90, position: 'insideRight' }} />
                      <Tooltip />
                      <Area yAxisId="left" type="monotone" dataKey="latency" name="Latency (ms)" stroke="#ef4444" fill="#fee2e2" fillOpacity={0.6} />
                      <Area yAxisId="right" type="monotone" dataKey="rps" name="Requests / Sec" stroke="#2563eb" fill="#dbeafe" fillOpacity={0.6} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Recommendations Box */}
              <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 text-xs space-y-2">
                <span className="font-bold text-slate-800 block">DDoS Mitigation & Hardening Findings:</span>
                <ul className="space-y-1 text-slate-600 list-disc pl-4">
                  {ddosData.recommendations.map((rec, i) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-xl border border-slate-200 p-8 text-center shadow-xs">
              <Activity className="w-12 h-12 text-slate-300 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-slate-700">Ready to Benchmark Resilience</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                Configure concurrency workers and duration above to analyze server throughput, rate-limit thresholds, and anti-DDoS behaviors.
              </p>
            </div>
          )}
        </>
      )}

      {/* CEH DDoS Attack Vectors Lab */}
      {activeTab === 'ceh-vectors' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3">CEH v13 Attack Profiles</h3>
            {attackVectors.map((v) => (
              <div
                key={v.id}
                onClick={() => setSelectedAttackVector(v.id as any)}
                className={`p-3 rounded-lg border transition-all cursor-pointer ${
                  selectedAttackVector === v.id
                    ? 'border-blue-600 bg-blue-50/50 shadow-2xs'
                    : 'border-slate-200 hover:border-slate-300 bg-white'
                }`}
              >
                <div className="flex justify-between items-center mb-1">
                  <span className="font-bold text-xs text-slate-800">{v.title}</span>
                </div>
                <span className="text-[10px] text-blue-600 font-mono block">{v.type}</span>
              </div>
            ))}
          </div>

          <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <div>
                  <h3 className="text-sm font-bold text-slate-800">{currentVector.title}</h3>
                  <span className="text-xs font-mono text-slate-400">{currentVector.cve}</span>
                </div>
                <span className="px-2.5 py-1 bg-red-100 text-red-800 rounded text-xs font-bold font-mono">
                  {currentVector.type}
                </span>
              </div>

              <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-xs space-y-2">
                <strong className="text-slate-700 block">Attack Mechanics:</strong>
                <p className="text-slate-600 leading-relaxed text-[11px]">{currentVector.description}</p>
                <div className="pt-2 border-t border-slate-200 text-red-700 font-medium">
                  Impact: {currentVector.impact}
                </div>
              </div>

              <div className="bg-blue-50/60 p-4 rounded-lg border border-blue-200 text-xs space-y-1.5">
                <strong className="text-blue-900 block flex items-center gap-1.5">
                  <Shield className="w-4 h-4 text-blue-600" /> CEH Defensive Hardening:
                </strong>
                <p className="text-blue-800 text-[11px] leading-relaxed">{currentVector.mitigation}</p>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-100 text-[10px] text-slate-400 flex justify-between">
              <span>CEH v13 Certified Ethical Hacker Curriculum</span>
              <span>Module 13 & Module 10 Standard</span>
            </div>
          </div>
        </div>
      )}

      {/* Defense Rules Generator */}
      {activeTab === 'defense-rules' && (
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-blue-600" />
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-600">
                Production DDoS Hardening Configurations
              </h3>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">Nginx / Apache / Linux Kernel</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Nginx Rate Limit */}
            <div className="bg-slate-900 text-slate-200 p-4 rounded-lg font-mono text-xs space-y-2">
              <div className="text-slate-400 text-[11px] border-b border-slate-800 pb-1 flex justify-between">
                <span># 1. Nginx Rate Limiting (nginx.conf)</span>
                <span className="text-blue-400">Layer 7</span>
              </div>
              <pre className="text-green-400 text-[11px] whitespace-pre-wrap">
{`# Rate limiting zone (10 requests/sec per IP)
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    limit_req zone=one burst=20 nodelay;
    limit_conn addr 10;
    client_body_timeout 5s;
    client_header_timeout 5s;
}`}
              </pre>
            </div>

            {/* Linux Kernel SYN Cookies */}
            <div className="bg-slate-900 text-slate-200 p-4 rounded-lg font-mono text-xs space-y-2">
              <div className="text-slate-400 text-[11px] border-b border-slate-800 pb-1 flex justify-between">
                <span># 2. Linux Kernel SYN Flood Defense (/etc/sysctl.conf)</span>
                <span className="text-emerald-400">Layer 4</span>
              </div>
              <pre className="text-green-400 text-[11px] whitespace-pre-wrap">
{`# Enable TCP SYN Cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15

# Drop Spoofed Bogus Packets
net.ipv4.conf.all.rp_filter = 1`}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
