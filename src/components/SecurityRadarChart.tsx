import React from 'react';
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip
} from 'recharts';
import { WebAuditResult, PortScanResult, StressTestResult } from '../types';

interface SecurityRadarChartProps {
  auditData: WebAuditResult | null;
  portData: { results: PortScanResult[]; openPortsCount: number } | null;
  ddosData: StressTestResult | null;
  theme?: string;
}

export const SecurityRadarChart: React.FC<SecurityRadarChartProps> = ({ auditData, portData, ddosData, theme }) => {
  const hasAudit = auditData !== null && auditData.reachable !== false;
  const hasPort = portData !== null;
  const hasDdos = ddosData !== null;

  // Derive scores (0-100) strictly from measured data
  const data = [
    {
      subject: 'Network Security',
      score: hasPort ? Math.max(0, 100 - (portData.openPortsCount * 10)) : 0,
    },
    {
      subject: 'HTTP Headers',
      score: hasAudit ? Math.min(100, (auditData.headers?.filter(h => h.present)?.length ?? 0) * 15) : 0,
    },
    {
      subject: 'SSL/TLS Crypto',
      score: hasAudit ? (auditData.tlsVersion === 'TLSv1.3' ? 100 : auditData.tlsVersion === 'TLSv1.2' ? 80 : auditData.tlsVersion ? 40 : 0) : 0,
    },
    {
      subject: 'DoS Resilience',
      score: hasDdos ? (ddosData.resilienceRating === 'Resilient' ? 100 : ddosData.resilienceRating === 'Moderate' ? 70 : 30) : 0,
    },
    {
      subject: 'Cleanliness / Vuln',
      score: hasAudit ? Math.max(0, 100 - (auditData.vulnerabilities?.length ?? 0) * 20) : 0,
    },
  ];

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs h-[300px]">
        <h3 className="text-xs font-black text-slate-900 uppercase mb-2">Security Posture Radar</h3>
        <ResponsiveContainer width="100%" height="100%">
        <RadarChart cx="50%" cy="50%" outerRadius="80%" data={data}>
            <PolarGrid stroke="#e2e8f0" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 10 }} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
            <Radar
            name="Security Score"
            dataKey="score"
            stroke="#6366f1"
            fill="#6366f1"
            fillOpacity={0.6}
            />
            <Tooltip
                contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
            />
        </RadarChart>
        </ResponsiveContainer>
    </div>
  );
};
