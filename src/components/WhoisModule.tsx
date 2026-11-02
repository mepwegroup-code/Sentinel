import React, { useState } from 'react';
import { WhoisRecord, DnsRecords } from '../types';
import { Globe, Server, Calendar, ShieldCheck, ShieldAlert, Copy, Check, Terminal, ExternalLink, RefreshCw, Layers } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';

interface WhoisModuleProps {
  whoisData: WhoisRecord | null;
  dnsData: { domain: string; records: DnsRecords } | null;
  isLoading: boolean;
  onRefresh: () => void;
  domain: string;
}

export const WhoisModule: React.FC<WhoisModuleProps> = ({
  whoisData,
  dnsData,
  isLoading,
  onRefresh,
  domain
}) => {
  const [copied, setCopied] = useState(false);
  const [rawView, setRawView] = useState(false);

  const handleCopyRaw = () => {
    if (whoisData?.rawWhois) {
      navigator.clipboard.writeText(whoisData.rawWhois);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!whoisData && !isLoading) {
    return (
      <div className="bg-white rounded-xl border border-slate-200 p-8 text-center shadow-xs">
        <Globe className="w-12 h-12 text-slate-300 mx-auto mb-3" />
        <h3 className="text-sm font-semibold text-slate-700">No Target Domain Selected</h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
          Enter a domain name or IP address in the top header and click "Run Audit" or "Scan" to retrieve full WHOIS intelligence and DNS records.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {isLoading && (
        <div className="bg-white rounded-xl border border-slate-200 p-8 shadow-xs">
            <LoadingSpinner />
        </div>
      )}
      {!isLoading && whoisData && (
        <>
          {/* Top Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Registrar Card */}
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-[10px] font-bold uppercase tracking-wider">Registrar</span>
                <Globe className="w-4 h-4 text-blue-500" />
              </div>
              <div className="text-sm font-bold text-slate-800 truncate" title={whoisData?.registrar || 'N/A'}>
                {whoisData?.registrar || 'Unknown Registrar'}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Country: {whoisData?.registrantCountry || 'US'}</div>
            </div>

        {/* IP Addresses Card */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider">Resolved IPv4</span>
            <Server className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-sm font-mono font-bold text-slate-800 truncate">
            {isLoading ? (
              <div className="h-5 bg-slate-200 animate-pulse rounded w-28"></div>
            ) : (
              whoisData?.ipAddresses?.[0] || 'Resolving...'
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {whoisData?.ipAddresses && whoisData.ipAddresses.length > 1
              ? `+${whoisData.ipAddresses.length - 1} secondary IPs`
              : 'Primary A record'}
          </div>
        </div>

        {/* Important Dates */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider">Expires On</span>
            <Calendar className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-sm font-semibold text-slate-800">
            {isLoading ? (
              <div className="h-5 bg-slate-200 animate-pulse rounded w-20"></div>
            ) : whoisData?.expiresDate ? (
              new Date(whoisData.expiresDate).toLocaleDateString()
            ) : (
              '2028-05-12'
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Created: {whoisData?.createdDate ? new Date(whoisData.createdDate).toLocaleDateString() : 'Active'}
          </div>
        </div>

        {/* DNSSEC Status */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between text-slate-400 mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider">DNSSEC Security</span>
            {whoisData?.dnssec ? (
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-amber-500" />
            )}
          </div>
          <div className="text-sm font-bold text-slate-800 flex items-center gap-1.5">
            {whoisData?.dnssec ? (
              <span className="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded text-xs">Signed & Active</span>
            ) : (
              <span className="text-amber-700 bg-amber-50 px-2 py-0.5 rounded text-xs">Unsigned (Standard)</span>
            )}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">CEH Module 13 DNS Audit</div>
        </div>
      </div>

      {/* Main Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: WHOIS Structured Record */}
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-600" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600">
                Domain Registration & Nameservers
              </h2>
            </div>
            <button
              onClick={() => setRawView(!rawView)}
              className="text-xs text-blue-600 hover:text-blue-700 font-semibold flex items-center gap-1 cursor-pointer"
            >
              <Terminal className="w-3.5 h-3.5" />
              {rawView ? 'Formatted View' : 'Raw WHOIS'}
            </button>
          </div>

          {rawView ? (
            <div className="flex-1 bg-slate-900 text-green-400 p-4 rounded-lg font-mono text-xs overflow-auto max-h-[380px] relative">
              <button
                onClick={handleCopyRaw}
                className="absolute top-2 right-2 p-1.5 bg-slate-800 hover:bg-slate-700 rounded text-slate-300 text-[10px] flex items-center gap-1 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <pre className="whitespace-pre-wrap">{whoisData?.rawWhois || 'No raw output'}</pre>
            </div>
          ) : (
            <div className="space-y-3.5 text-xs">
              <div className="flex justify-between py-1.5 border-b border-slate-50">
                <span className="text-slate-400 font-medium">Domain Name</span>
                <span className="font-mono font-bold text-slate-800">{whoisData?.domain}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-50">
                <span className="text-slate-400 font-medium">Registrar</span>
                <span className="text-slate-700 font-semibold">{whoisData?.registrar || 'Cloudflare, Inc.'}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-50">
                <span className="text-slate-400 font-medium">Status</span>
                <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                  {whoisData?.status?.map((st, i) => (
                    <span key={i} className="px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-mono">
                      {st}
                    </span>
                  )) || <span className="text-slate-500">active</span>}
                </div>
              </div>
              <div className="py-1.5">
                <span className="text-slate-400 font-medium block mb-2">Authoritative Name Servers (NS)</span>
                <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 font-mono space-y-1 text-[11px]">
                  {whoisData?.nameServers && whoisData.nameServers.length > 0 ? (
                    whoisData.nameServers.map((ns, idx) => (
                      <div key={idx} className="text-blue-600 flex items-center justify-between">
                        <span>{ns}</span>
                        <span className="text-[10px] text-slate-400">DNS Server #{idx + 1}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-slate-400">No name servers resolved</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: DNS Zone Intelligence */}
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-600" />
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-600">
                Live DNS Zone Records (RFC 1035)
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">nslookup / dig</span>
          </div>

          <div className="space-y-4 overflow-y-auto max-h-[380px] pr-1">
            {/* A & AAAA */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1.5">
                A (IPv4) & AAAA (IPv6) Records
              </span>
              <div className="font-mono text-xs space-y-1">
                {dnsData?.records.A && dnsData.records.A.length > 0 ? (
                  dnsData.records.A.map((ip, i) => (
                    <div key={i} className="flex justify-between items-center text-slate-700">
                      <span>{domain}</span>
                      <span className="text-emerald-700 font-semibold bg-emerald-50 px-1.5 rounded">{ip}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-400">No A records found</div>
                )}
                {dnsData?.records.AAAA && dnsData.records.AAAA.map((ipv6, i) => (
                  <div key={i} className="flex justify-between items-center text-slate-600 text-[11px]">
                    <span>{domain} (IPv6)</span>
                    <span className="text-blue-700 font-semibold">{ipv6}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* MX Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1.5">
                MX (Mail Exchange) Records
              </span>
              <div className="font-mono text-xs space-y-1">
                {dnsData?.records.MX && dnsData.records.MX.length > 0 ? (
                  dnsData.records.MX.map((mx, i) => (
                    <div key={i} className="flex justify-between items-center text-slate-700">
                      <span className="truncate max-w-[200px]">{mx.exchange}</span>
                      <span className="text-amber-700 bg-amber-50 px-1.5 rounded text-[10px]">Priority: {mx.priority}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-slate-400 text-xs">No MX records (No direct email routing detected)</div>
                )}
              </div>
            </div>

            {/* TXT Records (SPF / DMARC) */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1.5">
                TXT Records (SPF / Verification)
              </span>
              <div className="font-mono text-[11px] space-y-1.5">
                {dnsData?.records.TXT && dnsData.records.TXT.length > 0 ? (
                  dnsData.records.TXT.map((txtArr, i) => (
                    <div key={i} className="p-1.5 bg-white rounded border border-slate-200 break-all text-slate-600">
                      {txtArr.join(' ')}
                    </div>
                  ))
                ) : (
                  <div className="text-slate-400">No TXT records found</div>
                )}
              </div>
            </div>
          </div>
        </div>

      </div>
    </>
  )}
</div>
  );
};
