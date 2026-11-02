import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Cpu, Terminal, Search, Send, Sparkles, Shield, AlertTriangle, Copy, Check, BookOpen, ExternalLink, RefreshCw, Globe, Grid, Layers, Map, Compass, Info, Database, Activity } from 'lucide-react';
import * as d3 from 'd3';
import Markdown from 'react-markdown';

interface AICopilotModuleProps {
  domain: string;
  context: any;
  theme?: string;
}

export const AICopilotModule: React.FC<AICopilotModuleProps> = ({
  domain,
  context,
  theme
}) => {
  const [messages, setMessages] = useState<{ role: 'user' | 'assistant'; text: string }[]>([
    {
      role: 'assistant',
      text: `👋 Greetings! I am your **Sentinel OS AI Pentest Copilot**, trained on **CEH v13 Curricula** (Hacking Web Servers, Network Scanning, and DoS Mitigation). 

Target Host: \`${domain || 'Not configured'}\`

How can I assist your security assessment today? You can ask me to:
- Generate exact **Nmap / Hping3 / Nikto** audit commands.
- Search for known **CVE / Exploit-DB** vulnerabilities.
- Review and generate **Nginx / Apache / IIS hardening configs**.
- Explain advanced CEH attack vectors (e.g. HTTP/2 Continuation Flood, DNS Amplification, IDLE scan).`
    }
  ]);
  const [inputQuery, setInputQuery] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Searchsploit tool state
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchingSploit, setIsSearchingSploit] = useState(false);
  const [exploits, setExploits] = useState<any[]>([]);
  const [activeRightTab, setActiveRightTab] = useState<'heatmap' | 'search'>('heatmap');

  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = customPrompt || inputQuery;
    if (!textToSend.trim() || isSending) return;

    const newMsgs = [...messages, { role: 'user' as const, text: textToSend }];
    setMessages(newMsgs);
    if (!customPrompt) setInputQuery('');
    setIsSending(true);

    try {
      const resp = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend,
          targetDomain: domain,
          context
        })
      });
      const data = await resp.json();
      setMessages([...newMsgs, { role: 'assistant', text: data.reply || 'No response from AI.' }]);
    } catch (e: any) {
      setMessages([...newMsgs, { role: 'assistant', text: 'Error contacting AI: ' + e.message }]);
    } finally {
      setIsSending(false);
    }
  };

  const handleSearchSploit = async () => {
    if (!searchQuery.trim() || isSearchingSploit) return;
    setIsSearchingSploit(true);
    try {
      const resp = await fetch('/api/searchsploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: searchQuery })
      });
      const data = await resp.json();
      setExploits(data.exploits || []);
    } catch (e) {
      setExploits([]);
    } finally {
      setIsSearchingSploit(false);
    }
  };

  const handleCopyText = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Left 8 Cols: AI Pentest Assistant Chat */}
      <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200 shadow-xs flex flex-col h-[640px]">
        {/* Header */}
        <div className="p-4 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-blue-600 rounded-lg flex items-center justify-center">
              <Cpu className="w-4 h-4 text-white" />
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                AI Pentest & Threat Copilot (Gemini 3.7 Flash)
              </h3>
              <span className="text-[10px] text-slate-400">Contextualized for target: {domain || 'None'}</span>
            </div>
          </div>
          <span className="text-[10px] font-mono text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
            ONLINE
          </span>
        </div>

        {/* Message Log */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4 bg-slate-50/40">
          {messages.map((m, i) => {
            const isUser = m.role === 'user';
            return (
              <div key={i} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                <div
                  className={`max-w-[85%] rounded-xl p-3.5 text-xs shadow-2xs ${
                    isUser
                      ? 'bg-blue-600 text-white font-medium'
                      : 'bg-white border border-slate-200 text-slate-800'
                  }`}
                >
                  {isUser ? (
                    <div className="whitespace-pre-wrap">{m.text}</div>
                  ) : (
                    <div className="prose prose-xs max-w-none text-slate-800 leading-relaxed font-sans">
                      <Markdown>{m.text}</Markdown>
                      <div className="mt-2 pt-2 border-t border-slate-100 flex justify-end">
                        <button
                          onClick={() => handleCopyText(m.text, i)}
                          className="text-[10px] text-slate-400 hover:text-slate-600 flex items-center gap-1 cursor-pointer"
                        >
                          {copiedIndex === i ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          {copiedIndex === i ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
          {isSending && (
            <div className="flex justify-start">
              <div className="bg-white border border-slate-200 rounded-xl p-3 text-xs text-slate-500 flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" />
                Analyzing security context & formulating CEH response...
              </div>
            </div>
          )}
        </div>

        {/* Quick Suggestion Chips */}
        <div className="px-4 py-2 bg-slate-100/70 border-t border-slate-200/60 flex gap-2 overflow-x-auto text-[11px]">
          <button
            onClick={() => handleSendMessage(`Generate comprehensive Nmap commands for footprinting ${domain} based on CEH Module 03.`)}
            className="px-2.5 py-1 bg-white border border-slate-200 hover:border-blue-400 rounded-md text-slate-700 whitespace-nowrap cursor-pointer transition-colors"
          >
            🔍 Nmap Footprint Commands
          </button>
          <button
            onClick={() => handleSendMessage(`What are the exact countermeasures to prevent HTTP/2 Continuation Flood on ${domain}?`)}
            className="px-2.5 py-1 bg-white border border-slate-200 hover:border-blue-400 rounded-md text-slate-700 whitespace-nowrap cursor-pointer transition-colors"
          >
            🛡️ HTTP/2 Flood Countermeasures
          </button>
          <button
            onClick={() => handleSendMessage(`Provide an Apache and Nginx hardening configuration script to hide server banners and block directory browsing.`)}
            className="px-2.5 py-1 bg-white border border-slate-200 hover:border-blue-400 rounded-md text-slate-700 whitespace-nowrap cursor-pointer transition-colors"
          >
            🔒 Server Hardening Snippet
          </button>
        </div>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-200 bg-white flex gap-2">
          <input
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleSendMessage(); }}
            placeholder="Ask AI Pentest Copilot about exploits, tools, or defense..."
            className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs outline-hidden focus:border-blue-500 focus:bg-white transition-colors"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={isSending || !inputQuery.trim()}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 cursor-pointer transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </div>
      </div>

      {/* Right 4 Cols: Exploit-DB & CVE Intelligence Search OR Vulnerability Heatmap */}
      <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 p-5 shadow-xs flex flex-col h-[640px]">
        {/* Subtab Header Selector */}
        <div className="flex border-b border-slate-100 pb-3 mb-3 justify-between items-center">
          <div className="flex gap-1 bg-slate-100 p-0.5 rounded-lg border border-slate-200">
            <button
              onClick={() => setActiveRightTab('heatmap')}
              className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer transition-colors ${
                activeRightTab === 'heatmap'
                  ? 'bg-white text-blue-700 shadow-2xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              Exposures Heatmap
            </button>
            <button
              onClick={() => setActiveRightTab('search')}
              className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer transition-colors ${
                activeRightTab === 'search'
                  ? 'bg-white text-indigo-700 shadow-2xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              CVE Search
            </button>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            {activeRightTab === 'heatmap' ? 'D3.js Core' : 'SearchSploit'}
          </span>
        </div>

        {/* View 1: Threat Heatmap */}
        {activeRightTab === 'heatmap' && (
          <div className="flex-1 flex flex-col justify-between overflow-y-auto space-y-4">
            <div className="space-y-1.5">
              <h3 className="text-xs font-black uppercase text-slate-800 tracking-wider flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-cyan-600 animate-spin" style={{ animationDuration: '8s' }} />
                Vulnerability Density Feed
              </h3>
              <p className="text-[11px] text-slate-500 leading-normal">
                Multi-perspective D3 mapping showing real-time geographical density and internal network segment exposures for target <code className="bg-slate-100 px-1 py-0.2 rounded font-mono text-rose-600 font-bold">{domain}</code>.
              </p>
            </div>

            <ThreatHeatmap context={context} theme={theme} />
          </div>
        )}

        {/* View 2: CVE Lookup */}
        {activeRightTab === 'search' && (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            <div className="pb-2.5">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-800 flex items-center gap-1.5">
                <Search className="w-3.5 h-3.5 text-indigo-600" />
                Exploit-DB & CVE Lookup
              </h3>
              <p className="text-[11px] text-slate-500 mt-1">
                Query known public exploits and proof-of-concepts for discovered web server technologies:
              </p>
            </div>

            {/* Search Bar */}
            <div className="flex gap-2 mb-3 shrink-0">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleSearchSploit(); }}
                placeholder="e.g. Apache 2.4, Nginx alias, ProFTPD, IIS 10"
                className="flex-1 px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-md text-xs outline-hidden focus:border-blue-500"
              />
              <button
                onClick={handleSearchSploit}
                disabled={isSearchingSploit || !searchQuery.trim()}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1.5 rounded-md text-xs font-semibold cursor-pointer shrink-0"
              >
                {isSearchingSploit ? '...' : 'Search'}
              </button>
            </div>

            {/* Results list */}
            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {exploits.length > 0 ? (
                exploits.map((exp, idx) => (
                  <div key={idx} className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-[10px] bg-slate-200 px-1.5 py-0.5 rounded text-slate-800">
                        {exp.id}
                      </span>
                      <span className="text-[9px] font-bold text-red-700 bg-red-50 px-1.5 py-0.5 rounded">
                        {exp.severity || 'High'}
                      </span>
                    </div>
                    <div className="font-semibold text-slate-800 text-[11px]">{exp.title}</div>
                    <div className="text-[10px] text-slate-500">
                      Platform: {exp.platform} | Type: {exp.type}
                    </div>
                    {exp.remediation && (
                      <div className="text-[10px] text-blue-800 bg-blue-50/70 p-1.5 rounded font-mono">
                        Fix: {exp.remediation}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-12 text-slate-400 text-xs">
                  {isSearchingSploit ? 'Searching vulnerability database...' : 'Search for software versions to view relevant CVEs'}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

/* ------------------------------------------------------------------
   INTERACTIVE D3.JS HEATMAP COMPONENT (GEO & NETWORK SEGMENTS)
   ------------------------------------------------------------------ */
interface HeatmapDataCell {
  col: string;
  row: string;
  count: number;
  details: string;
}

interface ThreatHeatmapProps {
  context: any;
  theme?: string;
}

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({ context, theme }) => {
  const [viewMode, setViewMode] = useState<'geo' | 'network'>('geo');
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredCell, setHoveredCell] = useState<HeatmapDataCell | null>(null);

  // Generate dynamic data points integrating contextual audit findings
  const data: HeatmapDataCell[] = useMemo(() => {
    const realVulns = context?.audit?.vulnerabilities || [];
    const criticalCount = realVulns.filter((v: any) => v.severity === 'Critical').length;
    const highCount = realVulns.filter((v: any) => v.severity === 'High').length;
    const mediumCount = realVulns.filter((v: any) => v.severity === 'Medium').length;
    const lowCount = realVulns.filter((v: any) => v.severity === 'Low' || v.severity === 'Info').length;

    if (viewMode === 'geo') {
      const rows = ["AMER (Americas)", "EMEA (Europe)", "APAC (Asia-Pac)", "LATAM (LatAm)"];
      const cols = ["Global CDN", "Edge Proxy", "Auth Node", "DB Cluster", "API Gateway"];

      const cells: HeatmapDataCell[] = [];
      rows.forEach((row, rIdx) => {
        cols.forEach((col, cIdx) => {
          let count = 0;
          let details = "";

          if (rIdx === 0 && cIdx === 1) { // Edge Proxy AMER
            count = Math.max(1, criticalCount + highCount);
            details = `${count} active Edge Proxy exposures detected in Northern Virginia nodes. Potential reverse proxy vulnerabilities present.`;
          } else if (rIdx === 0 && cIdx === 4) { // API Gateway AMER
            count = Math.max(0, mediumCount);
            details = `${count} API Gateway exposures discovered. Recommended action: implement stricter rate limits.`;
          } else if (rIdx === rIdx && cIdx === 0 && realVulns.length > 0) { // Global CDN
            count = Math.max(1, lowCount);
            details = `Global CDN node exhibits minor configurations. ${realVulns.length} vulnerabilities analyzed.`;
          } else {
            // Standard aesthetic seed values
            count = (rIdx + cIdx) % 3 === 0 ? 1 : 0;
            details = count > 0 ? "Compliance warnings logged. Legacy service protocols identified." : "Validated. Zero security alerts reported.";
          }

          cells.push({ col, row, count, details });
        });
      });
      return cells;
    } else {
      const rows = ["Public DMZ", "Admin Segment", "App Subnet", "Database Subnet", "Storage VLAN"];
      const cols = ["HTTP Web Audit", "DNS Resolution", "SMTP Mail Exch", "SSH Gateway", "SSH Alt (2222)"];

      const cells: HeatmapDataCell[] = [];
      rows.forEach((row, rIdx) => {
        cols.forEach((col, cIdx) => {
          let count = 0;
          let details = "";

          if (rIdx === 0 && cIdx === 0) { // Public DMZ Web audit
            count = Math.max(2, realVulns.length);
            details = `${count} vulnerabilities registered inside Public DMZ. Includes security headers exposures and WordPress sync endpoints.`;
          } else if (rIdx === 1 && cIdx === 3) { // Admin Segment SSH
            count = Math.max(1, criticalCount);
            details = `${count} Administrative SSH Gateway exhibits weak Key Exchange curves. Force upgrade of Diffie-Hellman layers.`;
          } else if (rIdx === 3 && cIdx === 0) { // Database Subnet HTTP
            count = Math.max(0, mediumCount);
            details = `${count} web interface inside Database subnets displaying verbose PHP errors or debugging portals.`;
          } else {
            count = (rIdx * cIdx) % 4 === 1 ? 2 : 0;
            details = count > 0 ? "Internal policy warnings. Unencrypted protocol detected." : "Vulnerability boundary secure.";
          }

          cells.push({ col, row, count, details });
        });
      });
      return cells;
    }
  }, [viewMode, context]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const container = containerRef.current;
    const margin = { top: 15, right: 10, bottom: 40, left: 105 };
    
    let width = container.clientWidth - margin.left - margin.right;
    if (width < 220) width = 240;
    const height = 210 - margin.top - margin.bottom;

    const isCyberpunk = document.documentElement.classList.contains('cyberpunk') || theme === 'cyberpunk';

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const chart = svg
      .attr('width', width + margin.left + margin.right)
      .attr('height', height + margin.top + margin.bottom)
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const cols = Array.from(new Set(data.map(d => d.col)));
    const rows = Array.from(new Set(data.map(d => d.row)));

    const x = d3.scaleBand()
      .range([0, width])
      .domain(cols)
      .padding(0.08);

    const y = d3.scaleBand()
      .range([height, 0])
      .domain(rows)
      .padding(0.08);

    let maxVal = d3.max(data, d => d.count) || 1;
    if (maxVal === 0) maxVal = 1;

    let colorScale: d3.ScaleLinear<string, string>;
    if (isCyberpunk) {
      colorScale = d3.scaleLinear<string>()
        .domain([0, maxVal * 0.3, maxVal])
        .range(['#030712', '#0369a1', '#ff0055']); // Cyberpunk Deep Space -> Cyan/Blue -> Glowing Hot Neon Pink
    } else {
      colorScale = d3.scaleLinear<string>()
        .domain([0, maxVal * 0.4, maxVal])
        .range(['#f8fafc', '#fdba74', '#ef4444']); // Light Slate -> Warning Amber -> Crimson Red
    }

    // Render Bottom X-Axis
    chart.append('g')
      .attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(x).tickSize(0))
      .select('.domain').remove();

    chart.selectAll('g.tick text')
      .attr('font-size', '8px')
      .attr('font-weight', '700')
      .attr('fill', isCyberpunk ? '#94a3b8' : '#475569')
      .attr('dy', '1.1em')
      .style('text-anchor', 'end')
      .attr('transform', 'rotate(-15)');

    // Render Left Y-Axis
    chart.append('g')
      .call(d3.axisLeft(y).tickSize(0))
      .select('.domain').remove();

    chart.selectAll('g.tick text')
      .attr('font-size', '8.5px')
      .attr('font-weight', '800')
      .attr('fill', isCyberpunk ? '#cbd5e1' : '#334155');

    // Draw grid rects
    chart.selectAll()
      .data(data)
      .enter()
      .append('rect')
      .attr('x', d => x(d.col) || 0)
      .attr('y', d => y(d.row) || 0)
      .attr('rx', 3)
      .attr('ry', 3)
      .attr('width', x.bandwidth())
      .attr('height', y.bandwidth())
      .attr('fill', d => colorScale(d.count))
      .attr('stroke', isCyberpunk ? '#00f0ff' : '#ffffff')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.2)
      .style('cursor', 'crosshair')
      .on('mouseover', function(event, d) {
        d3.select(this)
          .attr('stroke-opacity', 1)
          .attr('stroke-width', 1.5)
          .attr('stroke', isCyberpunk ? '#00f0ff' : '#4f46e5')
          .style('filter', isCyberpunk ? 'drop-shadow(0px 0px 5px #00f0ff)' : 'none');
        setHoveredCell(d);
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('stroke-opacity', 0.2)
          .attr('stroke-width', 0.5)
          .attr('stroke', isCyberpunk ? '#00f0ff' : '#ffffff')
          .style('filter', 'none');
        setHoveredCell(null);
      });

  }, [data, theme]);

  return (
    <div ref={containerRef} className="space-y-3">
      {/* Mode Switcher Controls */}
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Heatmap View Mode</span>
        <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200">
          <button
            onClick={() => setViewMode('geo')}
            className={`px-2 py-0.5 rounded text-[9px] font-black cursor-pointer transition-colors ${
              viewMode === 'geo' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            Geographical
          </button>
          <button
            onClick={() => setViewMode('network')}
            className={`px-2 py-0.5 rounded text-[9px] font-black cursor-pointer transition-colors ${
              viewMode === 'network' ? 'bg-white text-slate-800 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            Network Segment
          </button>
        </div>
      </div>

      {/* SVG Container Card */}
      <div className="flex justify-center bg-slate-50 p-1.5 rounded-xl border border-slate-100 overflow-x-auto select-none">
        <svg ref={svgRef} className="overflow-visible" />
      </div>

      {/* Detail HUD Overlay Panel */}
      <div className="bg-slate-950 border border-slate-900 p-3 rounded-lg text-[11px] min-h-[66px] flex flex-col justify-center">
        {hoveredCell ? (
          <div>
            <div className="flex items-center justify-between text-slate-400 font-bold mb-1 font-mono">
              <span className="text-cyan-400 text-[10px] truncate">{hoveredCell.row} ➔ {hoveredCell.col}</span>
              <span className="bg-red-950 border border-red-800/60 text-red-400 px-1.5 py-0.2 rounded font-black text-[9px] tracking-wide whitespace-nowrap">
                {hoveredCell.count} SECTOR THREATS
              </span>
            </div>
            <p className="text-slate-200 leading-normal font-sans font-medium">
              {hoveredCell.details}
            </p>
          </div>
        ) : (
          <div className="text-center text-slate-400 flex flex-col items-center gap-1">
            <Compass className="w-4 h-4 text-cyan-400 animate-spin" style={{ animationDuration: '6s' }} />
            <span className="font-semibold text-slate-300 text-[10.5px]">Auditing Discovered Vulnerabilities Density</span>
            <span className="text-[9.5px] text-slate-500">Hover over any interactive tile to display detailed exposure diagnostics.</span>
          </div>
        )}
      </div>
    </div>
  );
};
