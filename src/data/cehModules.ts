import { CEHModuleInfo } from '../types';

export const CEH_MODULES: CEHModuleInfo[] = [
  {
    id: 'mod-13',
    moduleNumber: 13,
    title: 'Hacking Web Servers',
    category: 'Web Application & Server Security',
    summary: 'Comprehensive methodology for web server footprinting, banner grabbing, misconfiguration exploits, HTTP/2 Continuation flood, cache poisoning, and defensive countermeasures.',
    keyTechniques: [
      'Information Gathering (who.is, robots.txt, Netcraft, Subdomain Enumeration)',
      'Web Server Footprinting & Banner Grabbing (Netcat, Telnet, httprecon, Uniscan)',
      'HTTP/2 Continuation Flood Attacks & Stream Exhaustion (CVE-2024-27983)',
      'Directory Traversal & Misconfigured Nginx Alias / Apache ofBiz exploits',
      'HTTP Response Splitting, CRLF Injection & Web Cache Poisoning',
      'Frontjacking & Reverse Proxy Manipulation ($uri / $document_uri)',
      'Password Cracking (THC Hydra, Hashcat, Ncrack, CIRT default credentials)'
    ],
    tools: [
      'who.is / RDAP',
      'Netcat (nc -vv domain 80)',
      'Nikto2 / Nikto (-h target -Tuning x)',
      'Nmap (http-enum, http-headers, http-robots.txt)',
      'NginxPwner & Kyubi (Nginx alias traversal)',
      'THC Hydra / Hashcat',
      'Immunity CANVAS / Core Impact',
      'GFI LanGuard & OpenVAS'
    ],
    countermeasures: [
      'Disable directory browsing (Options -Indexes in Apache, directoryBrowse enabled="false" in IIS)',
      'Mask Server Banners (ServerTokens Prod, ServerSignature Off, RemoveServerHeader)',
      'Enforce HSTS, CSP, X-Frame-Options, X-Content-Type-Options nosniff',
      'Deploy Web Application Firewall (WAF / ModSecurity / Cloudflare)',
      'Segment Web Server in DMZ with restricted internal network access',
      'Patch web servers against HTTP/2 frame floods & validate SSL/TLS certificates',
      'Enforce 2FA/MFA, rate limiting, and automated account lockout'
    ]
  },
  {
    id: 'mod-03',
    moduleNumber: 3,
    title: 'Scanning Networks & Port Discovery',
    category: 'Network Reconnaissance',
    summary: 'Network host discovery, active/passive OS fingerprinting via TTL/TCP window, port scanning techniques (TCP Connect, SYN stealth, Xmas, FIN, ACK probe, IDLE scan) and IDS/firewall evasion.',
    keyTechniques: [
      'Host Discovery (ARP Ping, ICMP ECHO, UDP Ping, TCP SYN/ACK Ping sweeps)',
      'TCP Connect / Full-Open Scan (nmap -sT)',
      'Stealth SYN / Half-Open Scan (nmap -sS)',
      'Inverse TCP Scans (Xmas -sX, FIN -sF, NULL -sN, Maimon -sM)',
      'ACK Flag Probe & Window-Based Scan (nmap -sA, nmap -sW for firewall rules)',
      'IDLE / IPID Header Blind Scanning (nmap -sI with zombie host)',
      'OS Fingerprinting via TTL (Linux: 64, Windows: 128, Cisco/Solaris: 255)',
      'Evasion: Packet Fragmentation (-f), Source Port (-g 80), Decoys (-D RND:10), MAC Spoofing'
    ],
    tools: [
      'Nmap / Zenmap',
      'Hping3 (hping3 -S target -p 80, hping3 -1 ICMP sweep, --flood)',
      'Angry IP Scanner / SolarWinds NetScanTools',
      'Wireshark / Packet Sniffers',
      'Metasploit aux scanner modules',
      'Colasoft Packet Builder'
    ],
    countermeasures: [
      'Configure firewalls to drop unsolicited SYN packets and unexpected TCP flags',
      'Enable TCP SYN Cookies (sysctl -w net.ipv4.tcp_syncookies=1) to defeat SYN floods',
      'Filter ICMP at network perimeter & border routers',
      'Implement Ingress & Egress filtering on border routers to prevent IP spoofing',
      'Use stateful inspection firewalls and Snort/Suricata IDS/IPS',
      'Randomize TCP Initial Sequence Numbers (ISNs)'
    ]
  },
  {
    id: 'mod-10',
    moduleNumber: 10,
    title: 'Denial of Service (DoS/DDoS)',
    category: 'Availability & Resilience',
    summary: 'Mechanisms of volumetric, protocol, and application-layer DoS/DDoS attacks (SYN floods, HTTP/2 Continuation flood, DNS Amplification, HULK, Slowloris) and enterprise mitigation architectures.',
    keyTechniques: [
      'Application Layer HTTP/HTTPS Floods (HULK, HTTP POST floods)',
      'HTTP/2 Continuation Flood (Resource exhaustion via non-ending headers)',
      'SYN Flooding Attack (TCP connection table exhaustion)',
      'DNS Amplification (Recursive DNS queries with spoofed victim IP)',
      'Slowloris & Slow POST (Low-and-slow HTTP connection starvation)',
      'UDP / ICMP Smurf & Fraggle Floods'
    ],
    tools: [
      'HULK DoS',
      'Hping3 (--flood mode)',
      'LOIC / HOIC',
      'Slowloris.py',
      'Botnet Command & Control simulators'
    ],
    countermeasures: [
      'Cloud DDoS Scrubbing (Cloudflare Magic Transit, AWS Shield, Akamai)',
      'Aggressive HTTP Rate-Limiting per IP/Client (Nginx limit_req, Apache mod_ratelimit)',
      'Connection timeouts and keep-alive limits to thwart slowloris',
      'TCP SYN Proxying & SYN cookies on stateful firewalls',
      'Disable open DNS recursive resolvers on authoritative name servers',
      'BGP Anycast routing to distribute traffic loads across global PoPs'
    ]
  }
];
