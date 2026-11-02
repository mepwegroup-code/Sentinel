import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { Activity, Server, AlertTriangle, ShieldCheck, Network, Zap, RefreshCw, Globe, Layers } from 'lucide-react';
import { NetworkForceGraph } from './NetworkForceGraph';
import { GlobalThreatHeatmap } from './GlobalThreatHeatmap';
import { LanDevice } from '../types';

export const AdminDashboard: React.FC<{ logs: string[]; devices?: LanDevice[]; targetDomain?: string }> = ({ logs, devices, targetDomain }) => {
  const [networkDevices, setNetworkDevices] = useState<LanDevice[]>(devices || []);
  const [isFetchingDevices, setIsFetchingDevices] = useState<boolean>(false);
  const [activeVisualMode, setActiveVisualMode] = useState<'heatmap' | 'forcegraph' | 'both'>('both');

  // Auto-fetch latest scanned LAN devices if not passed directly
  useEffect(() => {
    if (!devices || devices.length === 0) {
      fetchLanDevices();
    }
  }, [devices]);

  const fetchLanDevices = async () => {
    setIsFetchingDevices(true);
    try {
      const res = await fetch('/api/lan-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientLocalIp: '192.168.1.105',
          clientSubnet: '192.168.1.0/24'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.devices) {
          setNetworkDevices(data.devices);
        }
      }
    } catch {
      // Fallback is handled inside NetworkForceGraph
    } finally {
      setIsFetchingDevices(false);
    }
  };

  // Mock data for load monitoring
  const data = [
    { time: '10:00', req: 400, latency: 24 },
    { time: '10:05', req: 300, latency: 13 },
    { time: '10:10', req: 600, latency: 98 }, // Spike
    { time: '10:15', req: 450, latency: 30 },
  ];

  return (
    <div className="space-y-6">
      {/* Visual Mode Navigation Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white p-3.5 rounded-2xl border border-slate-200 shadow-xs">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-blue-600" />
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
            SOC Visualization Mode:
          </span>
        </div>

        <div className="flex items-center p-1 bg-slate-100 rounded-xl border border-slate-200 gap-1 text-xs font-semibold">
          <button
            onClick={() => setActiveVisualMode('heatmap')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
              activeVisualMode === 'heatmap'
                ? 'bg-white text-emerald-600 shadow-xs font-bold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Globe className="w-3.5 h-3.5 text-emerald-500" />
            <span>Bản Đồ Nhiệt Mạng Của Bạn</span>
          </button>

          <button
            onClick={() => setActiveVisualMode('forcegraph')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
              activeVisualMode === 'forcegraph'
                ? 'bg-white text-indigo-600 shadow-xs font-bold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Network className="w-3.5 h-3.5 text-indigo-500" />
            <span>LAN Network Topology</span>
          </button>

          <button
            onClick={() => setActiveVisualMode('both')}
            className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all cursor-pointer ${
              activeVisualMode === 'both'
                ? 'bg-white text-slate-900 shadow-xs font-bold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-blue-500" />
            <span>Unified Multi-Layer View</span>
          </button>
        </div>
      </div>

      {/* 1. Real-time Global Threat Heatmap */}
      {(activeVisualMode === 'heatmap' || activeVisualMode === 'both') && (
        <div className="space-y-2">
          <GlobalThreatHeatmap targetDomain={targetDomain} />
        </div>
      )}

      {/* 2. Real-time Force Directed Network Topology Graph */}
      {(activeVisualMode === 'forcegraph' || activeVisualMode === 'both') && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-indigo-600" />
              <h2 className="text-base font-black text-slate-800 uppercase tracking-tight">
                Real-Time Local Network Topology & Traffic Flow Graph
              </h2>
            </div>
            <button
              onClick={fetchLanDevices}
              disabled={isFetchingDevices}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isFetchingDevices ? 'animate-spin' : ''}`} />
              <span>Sync Network Nodes</span>
            </button>
          </div>

          <NetworkForceGraph devices={networkDevices} />
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center gap-3 mb-4">
            <Activity className="w-6 h-6 text-indigo-600" />
            <h3 className="font-bold text-slate-800">Traffic Monitoring</h3>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="req" stroke="#4f46e5" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center gap-3 mb-4">
            <Server className="w-6 h-6 text-emerald-600" />
            <h3 className="font-bold text-slate-800">System Latency</h3>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="latency" fill="#10b981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
            <div className="flex items-center gap-3 mb-4">
                <ShieldCheck className="w-6 h-6 text-blue-600" />
                <h3 className="font-bold text-slate-800">Admin Controls</h3>
            </div>
            <div className="space-y-3">
                <button className="w-full text-left p-3 rounded-lg bg-blue-50 text-blue-700 font-semibold text-sm hover:bg-blue-100 transition-colors cursor-pointer">
                  Restart Core Services
                </button>
                <button className="w-full text-left p-3 rounded-lg bg-slate-50 text-slate-700 font-semibold text-sm hover:bg-slate-100 transition-colors cursor-pointer">
                  Clear System Cache
                </button>
            </div>
        </div>
      </div>

      <div className="bg-slate-900 rounded-xl p-6 shadow-md border border-slate-800">
        <h3 className="font-bold text-slate-100 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            System Logs (Security Audit)
        </h3>
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {logs.slice(-10).map((log, i) => (
            <p key={i} className="font-mono text-xs text-emerald-400">{log}</p>
          ))}
        </div>
      </div>
    </div>
  );
};
